# TDX Code Identity 보장 — Mainnet 정책 분석

## TL;DR

Story DKG validator를 **TDX TEE (Trusted Execution Environment)** 위에서 운영할 때, *"모든 검증자가 동일한 binary를 실행하고 있음을 on-chain DCAP attestation으로 증명"* 하는 것이 가능한지를 조사했습니다.

**결론**:
- **SGX는 native로 가능** (MRENCLAVE = enclave 코드 hash, 하드웨어가 자동 측정)
- **TDX는 architecturally 다른 모델**이라 위 보장을 cleanly 얻으려면 trade-off 필요
- **Mainnet 출시 시점에 정책 결정이 필요**: 운영 다양성 ↔ 보안 강도 사이에서 어느 균형점을 잡을지

이 문서는 *문제 정의 → TDX 개념 설명 → 조사 결과 → 3가지 정책 옵션*까지 정리합니다.

---

## 0. 용어 사전 (TDX 처음 보는 분들을 위해)

이 섹션을 먼저 읽고 본문으로 넘어가시길 추천합니다.

### TEE (Trusted Execution Environment)
하드웨어가 보호하는 격리된 실행 환경. 호스트 OS, 하이퍼바이저, 다른 사용자도 내부를 들여다보거나 변조할 수 없음. 두 가지 주요 구현:
- **Intel SGX**: process-level enclave (작은 워크로드 단위)
- **Intel TDX**: VM-level confidential compute (전체 VM 단위). AMD의 SEV-SNP가 동급 기술.

### SGX MRENCLAVE
"Measurement of Enclave"의 약자. SGX enclave 생성 시 하드웨어가 enclave가 로드한 모든 코드 페이지 + 초기 데이터 + 메타데이터를 SHA-256으로 측정한 32-byte 값. **Enclave 안의 코드는 MRENCLAVE를 변조할 수 없음** (하드웨어 강제). 같은 binary + 같은 매니페스트 → 같은 MRENCLAVE.

→ Story SGX validator가 on-chain attestation에서 *"이 정확한 코드를 실행 중"* 증명하는 데 사용됨.

### TDX TD (Trust Domain)
TDX가 보호하는 VM 단위. 일반 VM과 비슷하지만 메모리가 암호화되고 무결성이 보장됨. 호스트 OS/하이퍼바이저도 내용을 못 봄.

### TDVF (Trust Domain Virtual Firmware)
TD가 launch될 때 가장 먼저 실행되는 펌웨어. UEFI/BIOS에 해당. TDVF가 OS kernel을 로드하고 boot 단계를 진행함. 클라우드 TDX 제품에서는 **클라우드 vendor가 TDVF를 통제** (커스터마이징 불가).

### TD-shim
TDVF의 lightweight 버전. 일부 사용 사례 (직접 kernel boot 시나리오 등)에서 TDVF 대신 사용. Confidential containers 등에서 활용.

### MRTD (Measurement of Trust Domain)
TD launch 시점에 TDX 모듈이 자동 계산하는 SHA-384 값. 측정 대상:
- TDVF 코드 페이지
- 초기 RAM 상태 (TD가 시작할 때 메모리에 올라간 모든 페이지)
- TD_PARAMS (vCPU 수, 메모리 크기 등 launch parameters)

**MRTD는 하드웨어가 강제 측정**, TD 안의 코드가 변조 불가. SGX MRENCLAVE의 TDX 버전이라 볼 수 있지만, **측정 범위가 다름** — MRENCLAVE는 워크로드 코드, MRTD는 VM launch image.

### RTMR (Runtime Measurement Register)
TDX에는 RTMR0, RTMR1, RTMR2, RTMR3 — 총 4개의 SHA-384 누적 측정값. TPM의 PCR (Platform Configuration Register)에 해당. 각 RTMR은 hash chain:
```
RTMR_new = SHA384(RTMR_old || extension_data)
```
- **RTMR0**: TDVF configuration (UEFI Secure Boot 인증서 등)
- **RTMR1**: Kernel image 측정
- **RTMR2**: OS boot, initrd, cmdline
- **RTMR3**: Runtime extensions — **guest가 자유롭게 extend 가능**

→ RTMR3는 guest 코드가 임의 값으로 extend할 수 있음. 이게 *"누가 호출했는지"* 검증되지 않는 측정 채널.

### V4 Quote
TDX의 attestation 결과물. 240-byte 측정값(MRTD + RTMR0..3) + 64-byte report_data (guest 입력) + DCAP 서명 등을 포함. SGX의 quote에 해당.

### DCAP (Data Center Attestation Primitives)
Intel이 제공하는 attestation 검증 인프라. PCK (Provisioning Certification Key) certificate chain으로 quote의 진위를 검증. *"이 quote가 진짜 Intel TDX/SGX 하드웨어에서 발급됨"*을 보장.

### Paravisor
TDX의 표준 architecture 위에 추가로 얹히는 하이퍼바이저-내부 레이어. **Azure CVM TDX에서 사용하는 OpenHCL이 대표적**. Guest와 TDX 모듈 사이를 mediate함. Guest의 attestation 흐름을 paravisor가 통제하므로 일반 TDX 흐름과 다름. RTMR3 직접 extend 같은 기능을 guest에게 노출하지 않음.

### configfs-tsm
Linux kernel 6.7+에서 노출되는 TDX guest interface. `/sys/kernel/config/tsm/report/` 경로. Guest가 직접 quote 요청 가능. **베어메탈 + GCP/IBM/Alibaba 등 paravisor 없는 환경에서 사용** — Azure paravisor 환경에서는 노출 안 됨.

### Code Commitment / Binary Identity
On-chain attestation에서 *"이 검증자가 실행 중인 코드의 hash"*. Story DKG에서는:
- SGX: MRENCLAVE = code commitment
- TDX: keccak256(MRTD || RTMR0..3) = code commitment (현재 구현)

이 값이 화이트리스트에 등록된 *blessed release hash*와 일치해야 검증자가 등록 가능.

### Attestation Bypass
공격자가 *"검증된 코드가 실행 중"인 것처럼 quote를 위조*하는 행위. SGX는 하드웨어 강제로 우회 불가. TDX는 RTMR3 software-extend 메커니즘 때문에 우회 가능 (자세한 내용은 §3 참조).

---

## 1. 우리가 풀려는 문제

### 시나리오
Story Network는 DKG (Distributed Key Generation) 기반으로 분산 키 관리. 각 검증자가 TEE 안에서 부분 키 share를 보유. Threshold 이상의 share가 모이면 전체 키 재구성 가능.

**보안 가정**: 모든 검증자가 *동일한 검증된 story-kernel binary*를 실행해야 함. 다른 코드를 돌리는 검증자는 키 share를 유출하거나 악의적 가짜 share를 contribute할 수 있음.

### 요구사항
1. **Code identity 강제**: 각 검증자의 quote가 *blessed binary로 실행 중*임을 증명
2. **Cloud diversity**: 검증자가 다양한 vendor (Azure, GCP, IBM 등)에서 운영 가능. 단일 vendor 의존 회피.
3. **On-chain 검증**: Smart contract (TDXValidationHook)가 quote를 받아 위 두 가지를 검증 가능

### SGX에서는 어떻게 되어 있나
Story Network의 SGX 검증자는 이미 위 요구사항 모두 만족:
- **MRENCLAVE = blessed code hash**: 하드웨어 자동 측정. Gramine 매니페스트 + binary가 통째로 측정됨.
- **Cloud diversity**: SGX는 베어메탈, Azure SGX VM 등 여러 환경에서 동작
- **On-chain**: SGXValidationHook이 MRENCLAVE 화이트리스트 비교

→ TDX에서 *동일한 보장*을 얻을 수 있는지가 본 조사의 핵심 질문.

---

## 2. TDX vs SGX architecture 차이

### 핵심 구조적 차이
| 측면 | SGX | TDX |
|---|---|---|
| **워크로드 단위** | enclave = 워크로드 binary 자체 | TD = VM. 워크로드는 VM **안에서** 실행 |
| **하드웨어 측정 대상** | enclave 페이지 = 워크로드 코드 | TD launch state = TDVF + 초기 RAM. 워크로드 자체는 측정하지 않음 |
| **워크로드 identity 강제** | 자동 (enclave 생성 시) | **워크로드를 launch image에 박아 넣는 별도 단계 필요** — 안 박으면 측정 안 됨 |

**의미**: TDX는 *VM-level confidential computing*으로 설계됨. *"어떤 VM이 깨끗한 launch state로 시작됐나"*는 측정하지만, *"그 VM 안에서 어떤 워크로드가 실행되는지"*는 native primitive로 측정하지 않음. 이건 TDX의 design intent (기존 VM 워크로드를 그대로 confidential하게)에 맞는 디자인이지만, *워크로드 단위 identity 강제*에는 부적합.

### TDX의 측정값들이 의미하는 것

각 측정값을 *우리 binary identity 보장*에 활용 가능한지 분석:

| 측정값 | 통제권 | "우리 binary"를 capture? | 위조 가능? |
|---|---|---|---|
| **MRTD** | TD launch 환경 (cloud or 베어메탈) | ✅ binary가 launch image에 박혀 있을 때만 | 하드웨어 측정. **위조 불가** |
| **RTMR0..2** | TDVF + boot path | 간접적 (RTMR1=kernel, RTMR2=initrd) | TDVF가 정상 boot를 강제하는 한 위조 어려움 |
| **RTMR3** | TD 안의 어떤 코드든 extend 가능 | ❌ 우리가 직접 extend해야 함 | **위조 가능** — 다른 코드도 같은 값으로 extend 가능 |
| **V4.report_data (64B)** | TD 안의 코드 입력 | ❌ identity 정보 아님 (registration nonce 등 용도) | guest 통제 |

**핵심 통찰**:
- *Hardware-enforced + binary-bound* 측정값은 **MRTD 뿐**. 단, binary가 launch image에 baked-in일 때만.
- *Cross-vendor uniform* 측정값은 **RTMR3 뿐** (guest 통제). 단, software-extend라 위조 가능.
- **둘 다 만족하는 측정값은 없음** — TDX architectural fact.

---

## 3. RTMR3 attestation의 약점 (왜 hardware-enforced가 아닌가)

### "RTMR3 == hash(binary)" 검증의 의미

만약 우리 kernel이 시작 시 `RTMR3 ← SHA384(self_binary)` extend하고, on-chain hook이 `RTMR3 == expected_hash`를 검증한다면, 이게 보장하는 것은:

> *"이 quote가 발급된 TD 안의 어떤 코드가 RTMR3에 expected_hash로 extend하는 호출을 했다."*

이게 전부.

### 무엇을 보장하지 못하는가

| 명제 | 보장? |
|---|---|
| Quote가 진짜 Intel TDX 하드웨어에서 발급됨 | ✅ (DCAP 서명) |
| TD 안에서 누군가 RTMR3.EXTEND를 우리 hash로 호출함 | ✅ |
| **그 호출자가 우리 binary의 startup 코드였음** | ❌ |
| **TD 안에 다른 악성 코드가 동시에 돌고 있지 않음** | ❌ |
| **Operator가 우리 binary를 실제로 deploy해서 실행했음** | ❌ |

### 공격 시나리오 (concrete)

공격자가 자기 TDX 하드웨어 (cloud rental 또는 자체 운영)를 가정:
1. 악의적 kernel 작성. 시작 시 `RTMR3 ← SHA384(legit_story_kernel_binary)` extend (hash 값을 미리 계산해둠).
2. **legit binary는 실행하지 않고** 키 유출하는 악성 코드만 실행.
3. DCAP V4 quote 생성 — 진짜 TDX 하드웨어 서명, RTMR3 = expected 값.
4. On-chain hook 통과: *"DCAP valid + RTMR3 매치 → 통과"*.
5. 공격자가 fake validator로 DKG 참여. 자기 share 평문 보유.

### 왜 이게 가능한가

TDX의 `TDG.MR.RTMR.EXTEND` instruction은:
- *어떤* 데이터로 extend됐는지 보존 (해시 체인)
- *누가* 호출했는지 검증/기록 안 함

→ Quote에는 RTMR3 값만 있고, *"누가 그 값을 만들었는지"* 흔적 없음.

대조적으로 **SGX MRENCLAVE는 하드웨어가 enclave 생성 시 자동 측정**. Enclave 안의 코드가 손댈 수 없음 → caller identity 자동 보장.

### Threshold property가 어느 정도 완화

DKG는 *"t-of-n"* threshold scheme: t개 share 모여야 키 재구성. 1개 fake validator로는 키 노출 안 됨. 공격자가 t개 fake 동시 운영해야 위협 실현.

**Mitigation 효과**:
- 1 fake = DoS 능력만 (key compromise 안 됨)
- t fake collusion = key compromise. 공격 비용 = t × (TDX 하드웨어 + staking + governance pass).

→ Threshold 디자인 + economic deterrent로 *"single-actor 우회 시 피해"*를 제한 가능. 하지만 *근본적인 attestation 약점*은 그대로.

---

## 4. 베어메탈 + custom TDVF로 SGX-equivalent 가능 (이론상)

### 아이디어

Story Foundation이 *공식 TD launch image* 빌드:
```
[Reference TDVF (Intel 빌드)]
+ [TD-shim (story-foundation 커스텀)]
+ [Linux kernel (pinned version)]
+ [initrd (story-kernel binary 포함)]
+ [TD_PARAMS (예: 4 vCPU, 16GB RAM 고정)]
= TD launch image v1.0.0
```

빌드는 **reproducible** (같은 source → 같은 bytes). 결과 SHA-384 = `MRTD_v1.0.0`.

### 검증 흐름

1. 모든 검증자가 위 image를 자기 베어메탈 TDX 호스트에 deploy
2. TD launch 시 TDX 하드웨어가 MRTD 자동 계산 → 모두 동일한 `MRTD_v1.0.0`
3. On-chain hook:
   ```solidity
   require(approvedMRTDs[extractMRTD(quote)], "unapproved image");
   require(DCAP.verify(quote), "invalid attestation");
   ```
4. Binary 변경 → image 변경 → 새 MRTD → governance vote로 화이트리스트 추가

### 보안 분석

공격자가 우회하려면:
- **다른 binary 실행** → 다른 image → 다른 MRTD → 차단 ✅
- **같은 MRTD로 다른 코드 실행** → 불가능. TDX 하드웨어가 image bytes 그대로 launch 강제. legit binary가 그 안에 박혀 있어 자동 실행. ✅
- **MRTD 위조** → SHA-384 충돌 필요 → 사실상 불가능 ✅

→ **SGX MRENCLAVE와 hardware 보장 동등**. RTMR3 우회 gap이 닫힘.

### 단, 베어메탈에서만 가능

**모든 commodity cloud TDX가 TDVF를 cloud 통제로 봉인**. Custom TD launch image upload는 어느 cloud도 허용하지 않음 (조사 결과는 §5).

---

## 5. Cloud TDX 조사 결과

| Cloud | Custom OS image | Custom TDVF | MRTD 통제권 | "binary baking 가능?" |
|---|---|---|---|---|
| **Azure CVM TDX** | ⚠️ Microsoft-vetted images | ❌ OpenHCL paravisor 통제 | Microsoft | ❌ |
| **GCP Confidential VM TDX** | ✅ custom OS image upload (kernel ≥ 6.6, `TDX_CAPABLE` 태그) | ❌ Google 통제 | Google (RIM 공개) | ❌ |
| **IBM Cloud Confidential VM (Beta)** | ✅ kernel from Guest TDX tree 요구 | ❌ IBM 통제 | IBM | ❌ |
| **Alibaba Cloud ECS TDX** | ✅ custom OS image | ❌ Alibaba 통제 | Alibaba | ❌ |
| **베어메탈 TDX** | ✅ | ✅ 완전 통제 | 운영자 | ✅ |

### GCP의 명시적 입장 (가장 잘 문서화됨)

GCP 공식 문서:
> *"The initial launch component (the firmware) for TDX Confidential VM instances is measured into the MRTD, while the remaining boot chain is measured into the RTMRs."*
>
> *"Guest Firmware is an immutable component that is a trusted part of Google Cloud. When the TD is initialized, the guest firmware is loaded and measured together with the initial TD memory region to the MRTD register. Google provides the RIM value of Guest Firmware."*
>
> *"Users can extend the RTMR[3] register with user space measurements."*

해석:
- **MRTD = Google's TDVF measurement** (Google이 publish하는 RIM 값으로 customer가 trust anchor 사용 가능, 단 customer가 binary로 변조 불가)
- **RTMR[0]** = TDVF configuration (Google 통제)
- **RTMR[1]/[2]** = boot chain (kernel/initrd가 들어가지만 Google's UEFI loader가 측정 단계 통제)
- **RTMR[3]** = customer-controlled (유일하게 customer가 자유롭게 extend 가능)

### 왜 모든 cloud가 TDVF를 통제하는가

1. **Multi-tenancy 보안 책임** — TDVF가 잘못되면 호스트 전체가 위협받음. Cloud는 자기 책임 영역으로 통제.
2. **TDX 보안 패치 운영** — Intel이 TDVF 업데이트 발행하면 cloud가 일관 적용. Customer custom TDVF는 이 흐름 차단.
3. **Attestation 단순화** — Cloud가 TDVF measurement publish하면 customer가 trust anchor 사용. Custom TDVF는 customer마다 다 다른 trust anchor 필요해 운영 복잡.

이건 *TDX architecture 한계*가 아니라 *cloud 비즈니스 모델 한계*. TDX 표준 자체는 custom TDVF 허용 — cloud가 운영상 안 열어줄 뿐.

---

## 6. 추가 보안 함의 (여러 변수에 따라 commitment 변동)

Cloud commodity TDX에서 같은 vendor 안에서도 commitment가 달라지는 요인:

| 요인 | 영향 |
|---|---|
| **Machine type** (DC4es vs DC8es vs c3-standard-4 vs c3-standard-8) | TD_PARAMS의 vCPU/메모리 → MRTD 변동 |
| **OS image 버전** (Ubuntu 24.04 vs RHEL 9 vs 패치 시점) | RTMR1/RTMR2 변동 (kernel/initrd 다름) |
| **Cloud TDVF 업데이트** | MRTD 변동 (cloud가 *공지 없이* 롤아웃 가능) |
| **CPU 세대** (SPR vs EMR vs GNR) | platform config가 RTMR0에 → 잠재적 변동 |
| **Region** | 이론상 같지만 cloud별 region rollout 차이 가능 |

→ Cloud commodity TDX에서 commitment 화이트리스트 운영 시 **vendor 행동에 노출**됨. Cloud가 paravisor/TDVF 업데이트하면 모든 검증자의 commitment가 한 번에 invalidate. 사전 공지 없으면 chain 등록 즉시 실패.

---

## 7. 도출된 3가지 정책 옵션

위 조사 결과를 바탕으로, mainnet TDX 정책 결정 시 사실상 3가지 옵션:

### Option A — Commodity cloud TDX + RTMR3-only attestation

**모델**:
- Story-kernel이 시작 시 `RTMR3 ← SHA384(self_binary)` extend
- TDXValidationHook이 RTMR3만 검증 (MRTD/RTMR0..2 무시)
- 모든 cloud commodity CVM에서 검증자 운영 가능

**장점**:
- ✅ Validator 진입장벽 낮음 (cloud VM만 띄우면 됨)
- ✅ Cloud diversity 확보 (vendor 종속성 X)
- ✅ Binary 변경 → RTMR3 변경 → commitment 변경 (operator-visible)

**단점**:
- ⚠️ **Custom-TD attacker 우회 가능** — 공격자가 자기 TDX 하드웨어로 가짜 TD 띄워 RTMR3에 같은 hash extend → 우회. SGX-equivalent 보장 X.
- ⚠️ Cross-vendor uniformity 확보되지만 *"trust on hardware authenticity (DCAP) + economics"* 모델로 떨어짐.

**Mitigation**:
- DKG threshold 보수적 설정 (예: 2/3 super-majority)
- Validator selection diversity (단일 cloud로 쏠리지 않도록)
- Stake 요구 + slashing → fake validator 등록 비용 ↑
- Validator reputation/governance 가입 절차

### Option B — 베어메탈 TDX + 표준 launch image

**모델**:
- Story Foundation이 reference TDVF + TD-shim + kernel + initrd + binary baked-in image 빌드 + 배포
- 검증자는 베어메탈 TDX 호스트에 deploy
- TDXValidationHook이 MRTD 화이트리스트 검증
- Binary release마다 새 image + 새 MRTD + governance vote로 화이트리스트 추가

**장점**:
- ✅ **SGX-equivalent hardware 보장** — MRTD가 launch image 전체를 하드웨어 측정. 우회 불가.
- ✅ Cross-vendor uniform commitment (베어메탈 호스트 간 동일 image → 동일 MRTD)
- ✅ Vendor 행동 의존성 없음 (Story Foundation이 trust anchor)

**단점**:
- ❌ **Cloud commodity CVM 미지원** (Azure/GCP/IBM/Alibaba 모두 custom TDVF 안 받음)
- ❌ **Validator 진입장벽 높음**: 베어메탈 TDX 호스트 (Intel SPR/EMR 서버) 필요. Equinix Metal, Hivelocity 등 일부 베어메탈 임대 서비스만 제공. 자체 데이터센터 옵션도 있지만 비용/복잡도 큼.
- ❌ **빌드 파이프라인 운영 비용**: TDVF + initrd + binary reproducible build 시스템 + image 배포 + multi-host deploy + signed release 관리.
- ⚠️ TDX의 design intent (VM-level confidential)에 역행. SGX-style 워크로드 단위 attestation을 TDX architecture 위에 *재구현* 하는 것.

### Option D — Cloud commodity TDX + Decomposed whitelist (binary identity via TDVF-anchored RTMR1/RTMR2)

**핵심 통찰**:
- **TDVF는 cloud가 통제하지만 *trust anchor*로는 신뢰 가능** (MRTD가 자동 측정·publish됨). 그 TDVF가 **boot 단계에서 kernel image → RTMR1, initrd + cmdline → RTMR2** 로 측정하는 동작은 표준화되어 있음.
- **즉 binary를 initrd에 통째로 박아넣고 PID 1 init으로 띄우면**, 그 binary identity가 **RTMR2에 하드웨어 강제로 잡힘**. RTMR3 software-extend와 달리 *호출자 위조 불가능* — TDVF가 측정해야만 그 값이 나오기 때문.
- *이게 RTMR3 우회 gap을 닫는 메커니즘*: 공격자가 같은 RTMR1/RTMR2 값을 갖는 quote를 만들려면 진짜로 그 kernel + 그 initrd를 boot 시켜야 하고, 그러면 우리 binary가 init으로 실제 실행됨.

**Whitelist 구조 — 두 개의 mapping으로 분리**:
```solidity
mapping(bytes32 => bool) approvedCloudPlatforms;   // keccak256(MRTD || RTMR0) per cloud vendor + machine type + TDVF version
mapping(bytes32 => bool) approvedBinaryReleases;   // keccak256(RTMR1 || RTMR2) per Story release
```

**왜 분리(decomposed)된 화이트리스트인가**:
- 단일 `keccak256(MRTD||RTMR0||RTMR1||RTMR2)` 화이트리스트로 가면 거버넌스 비용이 **N(cloud SKU) × M(release)** — 매번 N×M 엔트리.
- (cloud, binary) 분리하면 **N + M** — 새 cloud SKU 추가 1건 거버넌스 vote, 새 binary release 추가 1건 거버넌스 vote. 독립적 lifecycle.
- *Cloud TDVF 업데이트 (vendor 주도) ↔ Story binary release (Foundation 주도)* 가 governance 차원에서 분리됨.

**Hook validation logic (Solidity 의사 코드)**:
```solidity
require(DCAP.verify(quote));
bytes32 cloudHash  = keccak256(quote[184:184+48] || quote[376:376+48]);  // MRTD || RTMR0
bytes32 binaryHash = keccak256(quote[424:424+48] || quote[472:472+48]);  // RTMR1 || RTMR2
require(approvedCloudPlatforms[cloudHash],  "TDX: unapproved cloud platform");
require(approvedBinaryReleases[binaryHash], "TDX: unapproved binary release");
// REPORT_DATA(data commitment) 검증은 기존과 동일
```

**왜 이게 RTMR3 extend bypass를 막는가**:
- TDVF가 user-space 코드 실행 *전에* kernel/initrd를 측정 → RTMR1/RTMR2에 누적. 이 측정은 TDVF가 강제 수행 (custom kernel/initrd라도 TDVF가 보는 bytes 그대로 측정됨).
- 공격자가 자기 악성 kernel + 악성 initrd로 boot하면 **RTMR1/RTMR2가 다른 값**으로 측정됨 → `approvedBinaryReleases`에 없음 → 차단.
- 매칭되는 (RTMR1, RTMR2)를 얻으려면 *우리가 publish한 그 kernel + 그 initrd*를 그대로 사용해야 하고, 그 initrd 안에 PID 1 init으로 박힌 우리 binary가 실제 실행됨. → SGX MRENCLAVE에 준하는 하드웨어 강제 보장.

**장점**:
- Hardware-enforced binary identity (binary 부분에 대해 SGX 동등 — TDVF measurement chain 신뢰가 trust anchor)
- Commodity cloud TDX에서 운영 가능 (베어메탈 불필요)
- Validator 진입장벽 낮음 (cloud VM 임대)
- Cloud TDVF 관리 ↔ Binary release 관리 독립 (decomposed trust)

**단점 / 운영 요구**:
- Cloud별 (MRTD, RTMR0) 엔트리 거버넌스 관리 필요 — 새 SKU/region 추가 시, cloud TDVF 업데이트 시 매번 vote
- **Reproducible kernel + initrd-with-binary 빌드 파이프라인** 필요 (SGX Gramine 매니페스트 + signed enclave 흐름과 유사한 운영 부담)
- Cloud TDVF 업데이트가 vendor 주도로 *예고 없이* 롤아웃 가능 → reactive governance, 새 (MRTD, RTMR0) 엔트리 추가될 때까지 검증자 일시 차단 가능
- **Azure paravisor 주의**: paravisor가 RTMR을 표준 TDVF와 다르게 extend할 수 있음. Paravisor 환경 지원 시 별도 검증 — STBN bundle path를 유지해야 할 가능성 (직접 검증 §10 참조).

### Option C — SGX-only mainnet (TDX 미지원)

**모델**:
- Mainnet 출시 시점에 TDX 검증자 미지원
- SGX 검증자만 허용 (Azure SGX VM, 베어메탈 SGX 등)
- TDX는 v2 별도 작업으로 분리

**장점**:
- ✅ 보안 모델 단순 + 깔끔 (SGX MRENCLAVE 하나로 통일)
- ✅ 기존 SGX 코드 그대로 활용
- ✅ TDX의 architectural ambiguity를 mainnet에 끌어들이지 않음

**단점**:
- ❌ Cloud diversity 축소 (SGX 지원 cloud로 한정)
- ❌ TDX 사용 의지가 있던 운영자/사용자 배제
- ❌ TDX 작업이 v1 mainnet에서 빠짐 (이미 투자한 TDX 코드는 v2까지 대기)

### 옵션 비교 요약

| 항목 | Option A | Option B | Option D | Option C |
|---|---|---|---|---|
| Code identity 강도 | 약함 (custom-TD 우회) | **강함 (SGX 동등)** | **강함** (binary 부분 SGX 동등, TDVF chain 신뢰 기반) | 강함 (SGX) |
| Validator 진입장벽 | 낮음 | 높음 (베어메탈 필요) | 낮음 (cloud VM) | 중간 (SGX VM) |
| Cloud diversity | 높음 | 낮음 (베어메탈만) | 높음 (commodity TDX 다수 vendor) | 중간 (SGX 지원 cloud) |
| 운영 복잡도 | 낮음 | **높음** (image build pipeline) | 중간 (initrd+kernel reproducible build) | 낮음 |
| Vendor 종속성 | 낮음 | 없음 | 중간 (cloud별 (MRTD,RTMR0) 추적) | SGX 지원 vendor 의존 |
| 거버넌스 비용 | O(1) | O(릴리스 수) | **O(cloud SKU + 릴리스 수)** — 분리 (decomposed) | O(릴리스 수) |
| TDX 가치 활용 | 부분적 | 본격적 (단 변형 사용) | 본격적 (TDVF chain 활용) | 없음 |
| 즉시 mainnet 가능? | 가능 | 빌드 시스템 구축 필요 | 빌드 파이프라인 + 거버넌스 준비 필요 | **즉시 가능** |

---

## 8. 추천 — 단계적 접근

저자 권고 (수정): **C (v1) → D (v1.x) → B (v2 if needed)** 단계적 진화. **Option A는 test-only / not for production** 으로 격하.

1. **v1 mainnet (단기)**: Option C — SGX-only로 출시. 보안 모델 명확하고, 운영 검증된 경로. TDX 작업은 architectural decision 정리하면서 별도 트랙.

2. **v1.x mainnet (중기, 권장)**: **Option D — 보안과 운영 복잡도의 최적 균형**. Commodity cloud TDX에서 운영하되, decomposed 화이트리스트로 binary identity를 TDVF chain (RTMR1/RTMR2) 위에 anchor. 새 cloud SKU·release lifecycle을 거버넌스가 독립적으로 관리. Validator 진입장벽 낮으면서도 RTMR3 software-extend 우회 gap이 닫힘. v1.x의 TDX 도입 1순위 후보.

3. **v2 mainnet (장기, 선택적)**: Option B 추가. 베어메탈 TDX 트랙을 *full-weight* 검증자로 인정 — Story Foundation reference TD launch image 빌드 시스템 구축. cloud TDVF에 대한 trust 가정을 제거할 필요가 있을 때 (예: 더 강한 보안 모델이 요구되거나, 특정 cloud의 TDVF 업데이트 거버넌스 부담이 운영상 문제가 될 때).

**Option A**: production tier로는 비추천. RTMR3 software-extend 약점이 *threshold + economics*만으로는 closed되지 않음 — custom-TD attacker가 t개 동시 fake validator를 staking으로 띄울 수 있다면 그대로 노출. *test environment 또는 PoC 시연용*으로만 활용.

이 단계적 접근의 장점:
- v1 mainnet timeline에 TDX architectural decision이 blocking 안 됨
- v1.x에서 Option D로 *cloud commodity TDX + 하드웨어 강제 binary identity* 둘 다 확보
- Option B는 *bare-metal 운영 의지가 있는 검증자 풀이 형성된 후*로 미룰 수 있음 — premature investment 회피

---

## 9. 팀 논의 필요한 질문들

문서를 공유받은 팀이 답해야 할 질문:

### 보안 정책 측면
1. RTMR3-only attestation의 우회 시나리오 (custom-TD attacker)를 받아들일 만한 위협 모델인가?
2. Threshold + economic deterrent 만으로 충분한가, 아니면 hardware-enforced binary identity가 *필수*인가?
3. Validator stake 가중치를 attestation 강도로 차등화 하는 것이 governance 차원에서 가능한가?

### 운영 측면
4. v1 mainnet timeline 안에 베어메탈 TDX validator를 운영할 의지/역량이 있는 검증자 후보가 있나?
5. Story Foundation이 reference TD launch image 배포 파이프라인을 운영할 수 있나? (TDVF reproducible build + 서명된 release + 주기적 업데이트)
6. Cloud TDX validator의 commitment 화이트리스트를 governance가 관리할 의지가 있나? (cloud의 paravisor/TDVF 업데이트 시 빠른 반응 필요)

### 사용자 경험 측면
7. v1 mainnet에서 SGX-only로 시작하면 잠재 검증자 풀이 어느 정도 축소되나?
8. TDX를 도입하지 않으면 잃는 시장/사용자가 있나?

---

## 10. 참고 자료

### 우리가 직접 검증한 사항 (이번 조사)

- **GCP TDX 코드 측정**: GCP `c3-standard-4` Confidential VM에서 측정한 TDX commitment `0x9c384bf86f3b96d200ebfc5b04a73cb4d0810fb0a33d8458a61ca8827ecc4678` (kernel 6.17 + Ubuntu 24.04 LTS Confidential VM image)
- **Azure TDX 코드 측정**: Azure `Standard_DC4es_v5`에서 측정한 commitment `0x56bd26902b05a0d9d6dcc4c13c7c7861fb1c79d47f166665a3a684df1d4f1a35` (paravisor-mediated)
- **두 cloud 측정값 다름**: vendor 통제 영역(MRTD/RTMR0..2)이 다른 결과
- **kernel binary 변경 후 Azure commitment 불변**: 우리 user-space binary는 측정 안 됨 확인 (current TDX 구현의 빈 곳)
- **GCP RTMR.EXTEND API 가용**: `/sys/class/misc/tdx_guest/measurements/rtmr3:sha384` 노출됨
- **Azure RTMR.EXTEND API 부재**: paravisor가 노출 안 함
- **Azure paravisor 모드에서도 RTMR1/RTMR2가 OS kernel/initrd를 반영함**: paravisor가 boot하는 OS의 kernel/initrd가 RTMR1/RTMR2에 측정됨을 확인. 단 GCP direct path와는 *측정값 자체는 다름* — paravisor가 보는 boot artifact가 다르기 때문.
- **결과: Azure paravisor TDX의 (RTMR1, RTMR2)는 GCP direct와 별개 tuple**: user-space binary가 동일해도 vendor마다 (RTMR1, RTMR2) 다름. Option D의 *per-cloud binary tuple* 가정이 실제 deployment에서 확인됨 (cross-cloud uniform 측정값을 얻으려면 vendor마다 동일한 custom OS image를 빌드·사용해야 함).

### 공식 문서

- [Intel TDX Module Architecture Spec](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-trust-domain-extensions.html)
- [Intel TDVF Design Guide](https://cdrdv2-public.intel.com/733585/tdx-virtual-firmware-design-guide-rev-004-20231206.pdf)
- [GCP Confidential VM Attestation](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation)
- [GCP TDX Custom Image Creation](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/create-custom-confidential-vm-images)
- [GCP Confidential VM Firmware Verification](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware)
- [IBM Cloud Confidential VM (TDX Beta)](https://cloud.ibm.com/docs/vpc?topic=vpc-about-confidential-computing-vpc)
- [Azure Confidential VM with Intel TDX](https://learn.microsoft.com/en-us/azure/confidential-computing/tdx-confidential-vm-overview)
- [Alibaba Cloud TDX Confidential Computing](https://www.alibabacloud.com/help/en/ecs/user-guide/build-a-tdx-confidential-computing-environment)
- [Cloud Hypervisor TDX docs (TDVF requirements)](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/intel_tdx.md)
- [td-shim spec](https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md)

### Story 관련 자료

- [story-kernel feat/tdx-support 브랜치](https://github.com/piplabs/story-kernel/tree/feat/tdx-support) — 현재 TDX 구현 (RTMR3-only 시도 직전 상태)
- [story-kernel/enclave/README.md](../enclave/README.md) — TEE backend 추상화
- [story-kernel/enclave/tdx/README.md](../enclave/tdx/README.md) — TDX backend 개요
- [story-kernel/enclave/tdx/setup/direct.md](../enclave/tdx/setup/direct.md) — Direct path 셋업 (configfs-tsm)
- [story-kernel/enclave/tdx/setup/paravisor.md](../enclave/tdx/setup/paravisor.md) — Paravisor path 셋업 (Azure)

---

## 부록 A: TDX measurement 흐름 다이어그램

```
TD launch:
  ┌─────────────────────────────────────────────────────────────┐
  │  TDX Module (CPU 내장, Intel-signed)                        │
  │   1. TDVF binary + 초기 RAM page들을 SHA-384로 측정         │
  │   2. 결과 → MRTD register (immutable for TD lifetime)       │
  │   3. RTMR0..3 모두 zero로 초기화                            │
  └─────────────────────────────────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  TDVF (TD Virtual Firmware) — UEFI 같은 역할                │
  │   - TDVF 자기 configuration → RTMR0에 extend                │
  │   - Kernel image SHA-384 → RTMR1에 extend                   │
  │   - initrd + cmdline → RTMR2에 extend                       │
  │   - kernel으로 control 이양                                 │
  └─────────────────────────────────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  Linux kernel (in TD)                                        │
  │   - 부팅 완료 → user space로 control 이양                    │
  │   - configfs-tsm 인터페이스 노출 (paravisor 없는 환경에서만) │
  └─────────────────────────────────────────────────────────────┘
                                │
                                ▼
  ┌─────────────────────────────────────────────────────────────┐
  │  User space (story-kernel 등)                                │
  │   - **자유롭게 RTMR3.EXTEND 호출 가능**                      │
  │   - 호출자 검증 없음 (caller identity 흔적 없음)             │
  │   - 누구든 임의 데이터로 extend 가능                         │
  └─────────────────────────────────────────────────────────────┘

V4 quote 생성 시:
  Quote에 다음 값들 포함:
   - MRTD          (TD launch image 측정, 하드웨어 자동)
   - RTMR0/1/2     (TDVF/kernel/boot chain 측정)
   - RTMR3         (user-space extension의 누적 결과)
   - report_data   (64 bytes guest 입력)
   - DCAP signature (Intel TDX 하드웨어 서명)

  → on-chain TDXValidationHook이 quote bytes를 받아 검증
```

## 부록 B: 본 문서에 반영된 구체적 측정값들 (devnet 검증 기준)

이번 조사에서 직접 측정해 검증한 값들:

| 항목 | 값 | 측정 환경 |
|---|---|---|
| Azure paravisor TDX commitment (현 구현) | `0x56bd26902b05a0d9d6dcc4c13c7c7861fb1c79d47f166665a3a684df1d4f1a35` | Azure `Standard_DC4es_v5`, OpenHCL paravisor |
| GCP direct TDX commitment (현 구현) | `0x9c384bf86f3b96d200ebfc5b04a73cb4d0810fb0a33d8458a61ca8827ecc4678` | GCP `c3-standard-4`, europe-west4-a, kernel 6.17 |
| Azure에서 binary 재빌드 후 commitment | **변화 없음** (`0x56bd26...` 유지) | RTMR이 user-space binary 측정 안 함 확인 |
| GCP MRTD | `0xfeb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162` | Google's TDVF measurement |
| GCP RTMR3 (extend 전) | `0x000...000` (48 bytes 모두 zero) | direct path 기본 상태 |

→ 위 측정값들이 *"vendor마다 commitment 달라짐 + user-space binary는 측정 안 됨"*을 실제 데이터로 확인.

---

*문서 작성: 2026-05-10. 추가 자료 또는 정정 사항이 있으면 PR로 업데이트 부탁드립니다.*
