package main

import (
	"context"
	"fmt"
	"math/big"
	"time"

	flag "github.com/spf13/pflag"

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
	"https://eth-sepolia-public.unifra.io",
	"https://rpc.sepolia.ethpandaops.io",
	"https://rpc-sepolia.rockx.com",
	"wss://sepolia.gateway.tenderly.co",
}

const (
	sepoliaProcessRegistry = "0x3d0b39c0239329955b9F0E8791dF9Aa84133c861"
	sepoliaOrgRegistry     = "0xd512481d0Fa6d975f9B186a9f6e59ea8E12D2C2b"
)

func main() {
	privKey := flag.String("privkey", "", "private key to use for the Ethereum account")
	sepolia := flag.Bool("sepolia", false, "use sepolia dev deployment")
	w3rpc := flag.String("w3rpc", "http://localhost:8545", "web3 rpc endpoint")

	flag.Parse()
	log.Init("debug", "stdout", nil)

	var err error
	contracts := &web3.Contracts{}

	if *sepolia {
		contracts, err = web3.LoadContracts(&web3.Addresses{
			OrganizationRegistry: common.HexToAddress(sepoliaOrgRegistry),
			ProcessRegistry:      common.HexToAddress(sepoliaProcessRegistry),
		}, rpcs[0])
		if err != nil {
			log.Fatal(err)
		}

		for i := 1; i < len(rpcs); i++ {
			if err := contracts.AddWeb3Endpoint(rpcs[i]); err != nil {
				log.Warnw("failed to add endpoint", "rpc", rpcs[i], "err", err)
			}
		}

		if err := contracts.SetAccountPrivateKey(*privKey); err != nil {
			log.Fatal(err)
		}

		log.Infow("contracts initialized", "chainId", contracts.ChainID)

	} else {
		contracts, err = web3.DeployContracts(*w3rpc, *privKey)
		if err != nil {
			log.Fatal(err)
		}
		log.Infow("contracts deployed", "chainId", contracts.ChainID)
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
				log.Infow("new process found", "process", proc.ID)
			}
		}
	}()

	newOrgChan, err := contracts.MonitorOrganizationCreatedByPolling(ctx, time.Second*5)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		log.Info("monitoring new organizations")
		for {
			select {
			case <-ctx.Done():
				return
			case org := <-newOrgChan:
				log.Infow("new organization found", "organization", org.String())
			}
		}
	}()

	time.Sleep(20 * time.Second)

	orgAddr := contracts.AccountAddress()
	if _, err := contracts.CreateOrganization(orgAddr, &types.OrganizationInfo{
		Name:        fmt.Sprintf("Vocdoni test %x", orgAddr[:4]),
		MetadataURI: "https://vocdoni.io",
	}); err != nil {
		log.Errorw(err, "failed to create organization")
		return
	}

	curve := curves.New(curves.CurveTypeBN254)
	pubKey, _, err := elgamal.GenerateKey(curve)
	if err != nil {
		log.Errorw(err, "failed to generate key")
		return
	}
	x, y := pubKey.Point()

	_, _, err = contracts.CreateProcess(&types.Process{
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
		log.Errorw(err, "failed to create process")
		return
	}
	select {}
}
