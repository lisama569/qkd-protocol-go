// qkd 在本地模拟一次完整的 BB84 量子密钥分发会话。
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lisama569/qkd-protocol-go/qkd"
)

func main() {
	numQubits := flag.Int("n", 20000, "number of qubits Alice prepares")
	seed := flag.Int64("seed", 1, "session random seed (reproducible)")
	loss := flag.Float64("loss", 0, "channel loss in dB")
	eta := flag.Float64("eta", 1.0, "detector efficiency in (0,1]")
	dark := flag.Float64("dark", 0, "dark count probability per slot in [0,1)")
	threshold := flag.Float64("threshold", 0.11, "QBER abort threshold in (0,0.5)")
	sample := flag.Float64("sample", 0.2, "QBER sample fraction in (0,1)")
	eve := flag.Bool("eve", false, "enable intercept-resend eavesdropper")
	required := flag.Int("require", 0, "required minimum final key length in bits")
	flag.Parse()

	cfg := qkd.Config{
		NumQubits:          *numQubits,
		Seed:               seed,
		ChannelLossDB:      loss,
		DetectorEfficiency: eta,
		DarkCountProb:      dark,
		QBERThreshold:      threshold,
		SampleFraction:     sample,
		Eavesdropper:       eve,
		RequiredKeyBits:    required,
	}

	sess, err := qkd.NewSession(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config rejected:", err)
		os.Exit(2)
	}
	res, err := sess.Run()
	l := res.Ledger
	fmt.Printf("sent=%d detected=%d sifted=%d sampled=%d qber=%.4f\n",
		l.Sent, l.Detected, l.Sifted, l.Sampled, res.QBER)
	fmt.Printf("leak: ec=%d verify=%d pa=%d  final=%d conserved=%v\n",
		l.ECLeak, l.VerifyLeak, l.PALeak, l.Final, l.Conserved())
	if err != nil {
		fmt.Println("session failed:", res.Reason)
		os.Exit(1)
	}
	fmt.Printf("key (%d bits): %x...\n", l.Final, res.Key[:min(8, len(res.Key))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
