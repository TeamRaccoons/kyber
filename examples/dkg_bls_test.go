package examples

import (
	"log"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"

	// "go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

func Test_Example_DKG_BLS(t *testing.T) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	rand.Seed(time.Now().UnixNano())

	var suite = pairing.NewSuiteBn256()

	n := 7
	threshold := 3

	type node struct {
		dkg         *dkg.DistKeyGenerator
		pubKey      kyber.Point
		privKey     kyber.Scalar
		deals       []*dkg.Deal
		resps       []*dkg.Response
		secretShare *share.PriShare
	}

	nodes := make([]*node, n)
	pubKeys := make([]kyber.Point, n)

	// 1. Init the nodes
	for i := 0; i < n; i++ {
		privKey := suite.Scalar().Pick(suite.RandomStream())
		pubKey := suite.Point().Mul(privKey, nil)

		// TODO validate privKey is non-zero
		if privKey.Equal(suite.Scalar().Zero()) {
			panic("Cannot go with zero share")
		}

		pubKeys[i] = pubKey
		nodes[i] = &node{
			pubKey:  pubKey,
			privKey: privKey,
			deals:   make([]*dkg.Deal, 0),
			resps:   make([]*dkg.Response, 0),
		}
	}

	// 2. Create the DKGs on each node
	for i, node := range nodes {
		dkg, err := dkg.NewDistKeyGenerator(suite, nodes[i].privKey, pubKeys, threshold)
		require.NoError(t, err)
		node.dkg = dkg
	}

	// 3. Each node sends its Deals to the other nodes
	for _, node := range nodes {
		deals, err := node.dkg.Deals()
		require.NoError(t, err)
		for i, deal := range deals {
			nodes[i].deals = append(nodes[i].deals, deal)
		}
	}

	// 4. Process the Deals on each node and send the responses to the other
	// nodes
	for i, node := range nodes {
		for _, deal := range node.deals {
			resp, err := node.dkg.ProcessDeal(deal)
			require.NoError(t, err)
			for j, otherNode := range nodes {
				if j == i {
					continue
				}
				otherNode.resps = append(otherNode.resps, resp)
			}
		}
	}

	// 5. Process the responses on each node
	for _, node := range nodes {
		for _, resp := range node.resps {
			_, err := node.dkg.ProcessResponse(resp)
			require.NoError(t, err)
			// err = node.dkg.ProcessJustification(justification)
			// require.NoError(t, err)
		}
	}

	// 6. Check and print the qualified shares
	for _, node := range nodes {
		require.True(t, node.dkg.Certified())
		require.Equal(t, n, len(node.dkg.QualifiedShares()))
		require.Equal(t, n, len(node.dkg.QUAL()))
		t.Log("qualified shares:", node.dkg.QualifiedShares())
		t.Log("QUAL", node.dkg.QUAL())
	}

	// 7. Get the secret shares and public key
	// shares := make([]*share.PriShare, n)
	var publicKey kyber.Point
	// var pubPoly *share.PubPoly
	var commitments []kyber.Point
	for _, node := range nodes {
		distrKey, err := node.dkg.DistKeyShare()
		require.NoError(t, err)
		// shares[i] = distrKey.PriShare()
		publicKey = distrKey.Public()

		commitments = distrKey.Commitments()
		// pubPoly = distrKey.PubPoly
		node.secretShare = distrKey.PriShare()

		t.Log("new distributed public key:", publicKey)
	}

	pubPoly := share.NewPubPoly(suite, suite.Point().Base(), commitments)

	// 8. Sign with new subgroup (> threshold) should be sucesfully
	message := []byte("Hello world")
	sigShares := make([][]byte, 0)
	for i, node := range nodes {
		if i > threshold-1 {
			break
		}
		S, err := tbls.Sign(suite, node.secretShare, message)
		require.NoError(t, err)
		sigShares = append(sigShares, S)
	}

	sig, err := tbls.Recover(suite, pubPoly, message, sigShares, threshold, n)
	require.NoError(t, err)
	err = bls.Verify(suite, pubPoly.Commit(), message, sig)
	require.Nil(t, err)

	// 9. Sign with new subgroup (< threshold) should be failed
	sigShares = make([][]byte, 0)
	for i, node := range nodes {
		if i > threshold-2 {
			break
		}
		S, err := tbls.Sign(suite, node.secretShare, message)
		require.NoError(t, err)
		sigShares = append(sigShares, S)
	}
	_, err = tbls.Recover(suite, pubPoly, message, sigShares, threshold, n)
	require.Error(t, err)

	// 10. The following shows a re-share of the dkg key, which will invalidates
	// the current shares on each node and produce a new public key. After that
	// steps 3, 4, 5 need to be done in order to get the new shares and public
	// key.
	newNodes := make([]*node, n)
	// newDkgs := make([]*dkg.DistKeyGenerator, len(nodes))
	for i, oldNode := range nodes {
		share, err := oldNode.dkg.DistKeyShare()
		require.NoError(t, err)
		c := &dkg.Config{
			Suite:        suite,
			Longterm:     oldNode.privKey,
			OldNodes:     pubKeys,
			NewNodes:     pubKeys,
			Share:        share,
			Threshold:    threshold,
			OldThreshold: threshold,
		}
		newDkg, err := dkg.NewDistKeyHandler(c)
		require.NoError(t, err)

		newNodes[i] = &node{
			dkg:   newDkg,
			deals: make([]*dkg.Deal, 0),
			resps: make([]*dkg.Response, 0),
		}
	}
	// 10.3. Each node sends its Deals to the other nodes
	for _, node := range newNodes {
		deals, err := node.dkg.Deals()
		require.NoError(t, err)
		for i, deal := range deals {
			newNodes[i].deals = append(newNodes[i].deals, deal)
		}
	}

	// 10.4. Process the Deals on each node and send the responses to the other
	// nodes
	for i, node := range newNodes {
		for _, deal := range node.deals {
			resp, err := node.dkg.ProcessDeal(deal)
			require.NoError(t, err)
			for j, otherNode := range newNodes {
				if j == i {
					continue
				}
				otherNode.resps = append(otherNode.resps, resp)
			}
		}
	}

	// 10.5. Process the responses on each node
	for _, node := range newNodes {
		for _, resp := range node.resps {
			_, err := node.dkg.ProcessResponse(resp)
			require.NoError(t, err)
			// err = node.dkg.ProcessJustification(justification)
			// require.NoError(t, err)
		}
	}

	// 10.6. Check and print the qualified shares
	for _, node := range newNodes {
		require.True(t, node.dkg.Certified())
		require.Equal(t, n, len(node.dkg.QualifiedShares()))
		require.Equal(t, n, len(node.dkg.QUAL()))
	}

	// 10.7. Get the secret shares and public key
	var newPublicKey kyber.Point
	for _, node := range newNodes {
		distrKey, err := node.dkg.DistKeyShare()
		require.NoError(t, err)
		newPublicKey = distrKey.Public()
		node.secretShare = distrKey.PriShare()
		commitments = distrKey.Commitments()
		require.Equal(t, publicKey.Equal(newPublicKey), true)
	}

	// 11. Sign with new shares
	sigShares = make([][]byte, 0)
	for i, node := range newNodes {
		if i > threshold-1 {
			break
		}
		S, err := tbls.Sign(suite, node.secretShare, message)
		require.NoError(t, err)
		sigShares = append(sigShares, S)
	}
	// get new pub poly
	pubPoly = share.NewPubPoly(suite, suite.Point().Base(), commitments)
	sig, err = tbls.Recover(suite, pubPoly, message, sigShares, threshold, n)
	require.NoError(t, err)
	err = bls.Verify(suite, pubPoly.Commit(), message, sig)
	require.Nil(t, err)

	// 12. Mix between new node and old node will be failed
	sigShares = make([][]byte, 0)
	for i, node := range newNodes {
		if i > threshold-2 {
			break
		}
		if i == 0 {
			S, err := tbls.Sign(suite, nodes[i].secretShare, message)
			require.NoError(t, err)
			sigShares = append(sigShares, S)
		} else {
			S, err := tbls.Sign(suite, node.secretShare, message)
			require.NoError(t, err)
			sigShares = append(sigShares, S)
		}
	}
	sig, err = tbls.Recover(suite, pubPoly, message, sigShares, threshold, n)
	require.Error(t, err)
}
