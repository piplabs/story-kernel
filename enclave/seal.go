package enclave

import (
	"fmt"
	"os"

	"github.com/edgelesssys/ego/ecrypto"
	log "github.com/sirupsen/logrus"
)

func SealToFile(data []byte, filePath string) error {
	sealedData, err := ecrypto.SealWithUniqueKey(data, nil)
	if err != nil {
		return fmt.Errorf("failed to seal the data: %w", err)
	}

	if err := os.WriteFile(filePath, sealedData, 0600); err != nil {
		return fmt.Errorf("failed to write %s: %w", filePath, err)
	}
	log.Infof("%s is sealed and written successfully", filePath)

	return nil
}

func UnsealFromFile(filePath string) ([]byte, error) {
	sealed, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", filePath, err)
	}

	key, err := ecrypto.Unseal(sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal oracle key: %w", err)
	}

	return key, nil
}
