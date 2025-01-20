package main

import (
	"context"
	"flag"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/curves"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
	"github.com/vocdoni/vocdoni-z-sandbox/web3"
)

var rpcs = []string{
	"wss://sepolia.drpc.org",
	"https://sepolia.gateway.tenderly.co",
	"https://rpc.ankr.com/eth_sepolia",
	"https://eth-sepolia.public.blastapi.io",
	"https://1rpc.io/sepolia",
}

func main() {
	privKey := flag.String("privkey", "", "private key to use for the Ethereum account")
	flag.Parse()
	log.Init("debug", "stdout", nil)
	contracts, err := web3.NewContracts(&web3.Addresses{
		OrganizationRegistry: common.HexToAddress("0x3d0b39c0239329955b9F0E8791dF9Aa84133c861"),
		ProcessRegistry:      common.HexToAddress("0xd512481d0Fa6d975f9B186a9f6e59ea8E12D2C2b"),
	}, rpcs[0])
	if err != nil {
		log.Fatal(err)
	}
	log.Infow("contracts initialized", "chainId", contracts.ChainID)

	for i := 1; i < len(rpcs); i++ {
		if err := contracts.AddWeb3Endpoint(rpcs[i]); err != nil {
			log.Warnw("failed to add endpoint", "rpc", rpcs[i], "err", err)
		}
	}

	if err := contracts.SetAccountPrivateKey(*privKey); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	newProcChan, err := contracts.MonitorProcessCreationByPolling(ctx, time.Second*5)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		log.Info("monitoring new processes")
		for {
			select {
			case <-ctx.Done():
				return
			case proc := <-newProcChan:
				log.Infow("new process created", "process", proc.String())
			}
		}
	}()

	time.Sleep(20 * time.Second)

	orgInfo, err := contracts.Organization(contracts.AccountAddress())
	if err != nil {
		log.Fatal(err)
	}
	if orgInfo.MetadataURI == "" {
		log.Infof("organization not found, creating it")
		txHash, err := contracts.CreateOrganization(&types.OrganizationInfo{
			Name:        "Vocdoni",
			MetadataURI: "https://vocdoni.io",
		})
		if err != nil {
			log.Fatal(err)
		}
		log.Infow("organization created", "txHash", txHash.Hex())
	} else {
		log.Infow("organization info", "orgInfo", orgInfo)
	}

	curve := curves.New(curves.CurveTypeBN254)
	pubKey, _, err := elgamal.GenerateKey(curve)
	if err != nil {
		log.Fatal(err)
	}
	x, y := pubKey.Point()

	pid, txHash, err := contracts.CreateProcess(&types.Process{
		Status:         0,
		OrganizationId: contracts.AccountAddress(),
		EncryptionKey: &types.EncryptionKey{
			X: x,
			Y: y,
		},
		StateRoot:   util.RandomBytes(32),
		StartTime:   time.Now().Add(5 * time.Minute),
		Duration:    time.Hour,
		MetadataURI: "https://example.com/metadata",
		BallotMode: &types.BallotMode{
			MaxCount:        2,
			MaxValue:        *new(types.BigInt).SetUint64(100),
			MinValue:        *new(types.BigInt).SetUint64(0),
			MaxTotalCost:    *new(types.BigInt).SetUint64(0),
			MinTotalCost:    *new(types.BigInt).SetUint64(0),
			ForceUniqueness: false,
			CostFromWeight:  false,
		},
		Census: &types.Census{
			CensusRoot:   util.RandomBytes(32),
			MaxVotes:     new(big.Int).SetUint64(100),
			CensusURI:    "https://example.com/census",
			CensusOrigin: 0,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Infow("process created", "pid", pid.String(), "txHash", txHash.Hex())

	select {}
}
