package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/succinctlabs/gnark-plonky2-verifier/trusted_setup"
	"github.com/succinctlabs/gnark-plonky2-verifier/types"
	"github.com/succinctlabs/gnark-plonky2-verifier/variables"
	"github.com/succinctlabs/gnark-plonky2-verifier/verifier"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func runBenchmark(plonky2Circuit string, proofSystem string, profileCircuit bool, dummy bool, saveArtifacts bool) {
	commonCircuitData := types.ReadCommonCircuitData("testdata/" + plonky2Circuit + "/common_circuit_data.json")

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + plonky2Circuit + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + plonky2Circuit + "/verifier_only_circuit_data.json"))

	circuit := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
		CommonCircuitData:       commonCircuitData,
	}

	var p *profile.Profile
	if profileCircuit {
		p = profile.Start()
	}

	var builder frontend.NewBuilder
	if proofSystem == "plonk" {
		builder = scs.NewBuilder
	} else if proofSystem == "groth16" {
		builder = r1cs.NewBuilder
	} else {
		fmt.Println("Please provide a valid proof system to benchmark, we only support plonk and groth16")
		os.Exit(1)
	}

	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		fmt.Println("error in building circuit", err)
		os.Exit(1)
	}

	if profileCircuit {
		p.Stop()
		p.Top()
		println("r1cs.GetNbCoefficients(): ", r1cs.GetNbCoefficients())
		println("r1cs.GetNbConstraints(): ", r1cs.GetNbConstraints())
		println("r1cs.GetNbSecretVariables(): ", r1cs.GetNbSecretVariables())
		println("r1cs.GetNbPublicVariables(): ", r1cs.GetNbPublicVariables())
		println("r1cs.GetNbInternalVariables(): ", r1cs.GetNbInternalVariables())
	}

	if proofSystem == "plonk" {
		plonkProof(r1cs, plonky2Circuit, dummy, saveArtifacts)
	} else if proofSystem == "groth16" {
		groth16Proof(r1cs, plonky2Circuit, dummy, saveArtifacts)
	} else {
		panic("Please provide a valid proof system to benchmark, we only support plonk and groth16")
	}
}

func plonkProof(r1cs constraint.ConstraintSystem, circuitName string, dummy bool, saveArtifacts bool) {
	var pk plonk.ProvingKey
	var vk plonk.VerifyingKey
	var srs kzg.SRS = kzg.NewSRS(ecc.BN254)
	var err error

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + circuitName + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + circuitName + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{

		PublicInputs: proofWithPis.PublicInputs, Proof: proofWithPis.Proof,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	// Don't serialize the circuit for now, since it takes up too much memory
	// if saveArtifacts {
	// 	fR1CS, _ := os.Create("circuit")
	// 	r1cs.WriteTo(fR1CS)
	// 	fR1CS.Close()
	// }

	fmt.Println("Running circuit setup", time.Now())
	if dummy {
		fmt.Println("Using test setup")

		srs, err = test.NewKZGSRS(r1cs)

		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("Using real setup")

		fileName := "srs_setup"

		if _, err := os.Stat(fileName); os.IsNotExist(err) {
			trusted_setup.DownloadAndSaveAztecIgnitionSrs(174, fileName)
		}

		fSRS, err := os.Open(fileName)

		_, err = srs.ReadFrom(fSRS)

		fSRS.Close()

		if err != nil {
			panic(err)
		}
	}

	pk, vk, err = plonk.Setup(r1cs, srs)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if saveArtifacts {
		fPK, _ := os.Create("proving.key")
		pk.WriteTo(fPK)
		fPK.Close()

		if vk != nil {
			fVK, _ := os.Create("verifying.key")
			vk.WriteTo(fVK)
			fVK.Close()
		}

		fSolidity, _ := os.Create("proof.sol")
		err = vk.ExportSolidity(fSolidity)
	}

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	if saveArtifacts {
		fWitness, _ := os.Create("witness")
		witness.WriteTo(fWitness)
		fWitness.Close()
	}

	fmt.Println("Creating proof", time.Now())
	proof, err := plonk.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if saveArtifacts {
		fProof, _ := os.Create("proof.proof")
		proof.WriteTo(fProof)
		fProof.Close()
	}

	if vk == nil {
		fmt.Println("vk is nil, means you're using dummy setup and we skip verification of proof")
		return
	}

	fmt.Println("Verifying proof", time.Now())
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()
	fmt.Printf("proofBytes: %v\n", proofBytes)
}

func LoadGroth16ProverData(path string) (groth16.ProvingKey, error) {
	pkFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	pkReader := bufio.NewReader(pkFile)
	_, err = pk.ReadFrom(pkReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read pk file: %w", err)
	}
	pkFile.Close()
	return pk, nil
}

func loadProvingKeyandVerifyingKey(r1cs constraint.ConstraintSystem, dummy bool, saveArtifacts bool) (groth16.ProvingKey, groth16.VerifyingKey) {
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	// Check if vk and pk files exist
	// _, err = os.Stat("proving.key")
	// _, err1 := os.Stat("verifying.key")
	// if err == nil && err1 == nil {
	// 	vk, err = LoadGroth16VerifierKey("verifying.key")
	// 	if err != nil {
	// 		fmt.Println("Error loading verifying key:", err)
	// 		os.Exit(1)
	// 	}
	// 	pk, err = LoadGroth16ProverData("proving.key")
	// 	if err != nil {
	// 		fmt.Println("Error loading proving key:", err)
	// 		os.Exit(1)
	// 	}
	// 	return pk, vk
	// }

	if dummy {
		fmt.Println("Using dummy setup")
		pk, err = groth16.DummySetup(r1cs)
	} else {
		fmt.Println("Using real setup")
		pk, vk, err = groth16.Setup(r1cs)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if saveArtifacts {
		fPK, _ := os.Create("proving.key")
		pk.WriteTo(fPK)
		fPK.Close()

		if vk != nil {
			fVK, _ := os.Create("verifying.key")
			vk.WriteTo(fVK)
			fVK.Close()

			// Dump verification key as JSON
			vkJSON, err := json.Marshal(vk)
			if err != nil {
				fmt.Println("Error marshaling verification key to JSON:", err)
			}
			err = ioutil.WriteFile("verification_key.json", vkJSON, 0644)
			if err != nil {
				fmt.Println("Error writing verification key JSON file:", err)
			}
		}

		fSolidity, _ := os.Create("proof.sol")
		_ = vk.ExportSolidity(fSolidity)
	}

	return pk, vk
}

func groth16Proof(r1cs constraint.ConstraintSystem, circuitName string, dummy bool, saveArtifacts bool) {
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var err error

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + circuitName + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + circuitName + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}
	// Don't serialize the circuit for now, since it takes up too much memory
	// if saveArtifacts {
	// 	fR1CS, _ := os.Create("circuit")
	// 	r1cs.WriteTo(fR1CS)
	// 	fR1CS.Close()
	// }

	pk, vk = loadProvingKeyandVerifyingKey(r1cs, dummy, saveArtifacts)

	fmt.Println("Generating witness", time.Now())
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	if saveArtifacts {
		fWitness, _ := os.Create("witness")
		witness.WriteTo(fWitness)
		fWitness.Close()

		// Dump witness as JSON
		schema, _ := frontend.NewSchema(&assignment)
		witnessJSON, err := publicWitness.ToJSON(schema)
		if err != nil {
			fmt.Println("Error marshaling witness to JSON:", err)
		}
		err = ioutil.WriteFile("pubwitness.json", witnessJSON, 0644)
		if err != nil {
			fmt.Println("Error writing witness JSON file:", err)
		}

		bPublicWitness, _ := publicWitness.MarshalBinary()
		bPublicWitness = bPublicWitness[12:]
		publicWitnessStr := hex.EncodeToString(bPublicWitness)
		_ = ioutil.WriteFile("pubwitness.hex", []byte(publicWitnessStr), 0644)
	}

	fmt.Println("Creating proof", time.Now())
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if saveArtifacts {
		fProof, _ := os.Create("proof.proof")
		proof.WriteTo(fProof)
		fProof.Close()

		// Dump proof as JSON
		proofJSON, err := json.Marshal(proof)
		if err != nil {
			fmt.Println("Error marshaling proof to JSON:", err)
		}
		err = ioutil.WriteFile("proof.json", proofJSON, 0644)
		if err != nil {
			fmt.Println("Error writing proof JSON file:", err)
		}
	}

	if vk == nil {
		fmt.Println("vk is nil, means you're using dummy setup and we skip verification of proof")
		return
	}

	fmt.Println("Verifying proof", time.Now())
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	const fpSize = 4 * 8
	var buf bytes.Buffer
	proof.WriteRawTo(&buf)
	proofBytes := buf.Bytes()

	var (
		a [2]*big.Int
		b [2][2]*big.Int
		c [2]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	println("a[0] is ", a[0].String())
	println("a[1] is ", a[1].String())

	println("b[0][0] is ", b[0][0].String())
	println("b[0][1] is ", b[0][1].String())
	println("b[1][0] is ", b[1][0].String())
	println("b[1][1] is ", b[1][1].String())

	println("c[0] is ", c[0].String())
	println("c[1] is ", c[1].String())

}

func LoadGroth16VerifierKey(path string) (groth16.VerifyingKey, error) {
	vkFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open vk file: %w", err)
	}
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(vkFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read vk file: %w", err)
	}
	vkFile.Close()

	return vk, nil
}

func LoadGroth16Proof(path string) (groth16.Proof, error) {
	proofFile, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open proof file: %w", err)
	}
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(proofFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read proof file: %w", err)
	}
	proofFile.Close()

	return proof, nil
}

func LoadWitness(path string) {
	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + path + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + path + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	witness1 := witness.Vector().(fr_bn254.Vector)
	json1 := witness1.String()
	println("%s", json1)
}

func LoadAndVerifyProof(proofp string) {
	vk, err := LoadGroth16VerifierKey("verifying.key")
	if err != nil {
		fmt.Println("Error loading verifying key:", err)
		os.Exit(1)
	}

	proof, err := LoadGroth16Proof("proof.proof")
	if err != nil {
		fmt.Println("Error loading proof:", err)
		os.Exit(1)
	}

	proofWithPis := variables.DeserializeProofWithPublicInputs(types.ReadProofWithPublicInputs("testdata/" + proofp + "/proof_with_public_inputs.json"))
	verifierOnlyCircuitData := variables.DeserializeVerifierOnlyCircuitData(types.ReadVerifierOnlyCircuitData("testdata/" + proofp + "/verifier_only_circuit_data.json"))
	assignment := verifier.ExampleVerifierCircuit{
		Proof:                   proofWithPis.Proof,
		PublicInputs:            proofWithPis.PublicInputs,
		VerifierOnlyCircuitData: verifierOnlyCircuitData,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}

func main() {
	plonky2Circuit := flag.String("plonky2-circuit", "step", "plonky2 circuit to benchmark")
	proofSystem := flag.String("proof-system", "groth16", "proof system to benchmark")
	profileCircuit := flag.Bool("profile", false, "profile the circuit")
	dummySetup := flag.Bool("dummy", false, "use dummy setup")
	saveArtifacts := flag.Bool("save", true, "save circuit artifacts")

	flag.Parse()

	if plonky2Circuit == nil || *plonky2Circuit == "" {
		fmt.Println("Please provide a plonky2 circuit to benchmark")
		os.Exit(1)
	}

	fmt.Printf("Running benchmark for %s circuit with proof system %s\n", *plonky2Circuit, *proofSystem)
	fmt.Printf("Profiling: %t, DummySetup: %t, SaveArtifacts: %t\n", *profileCircuit, *dummySetup, *saveArtifacts)

	runBenchmark(*plonky2Circuit, *proofSystem, *profileCircuit, *dummySetup, *saveArtifacts)
}
