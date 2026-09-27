package agent

import "testing"

func TestParsePkgQuery(t *testing.T) {
	got := parsePkgQuery("pkg-1.21.3\t1.21.3\tFreeBSD\nos-dmidecode\t1.0\topnsense\n")
	if len(got) != 2 {
		t.Fatalf("len=%d", len(got))
	}
	if got[1].Name != "os-dmidecode" || got[1].SourceRepository != "opnsense" {
		t.Fatalf("unexpected package: %+v", got[1])
	}
}

func TestMarkPkgUpdates(t *testing.T) {
	packages := parsePkgQuery("pkg\t1.0\tFreeBSD\nos-dmidecode\t1.0\topnsense\ncurl\t8.0\tFreeBSD\n")
	packages = markPkgUpdates(packages, "pkg-1.0 < needs updating (index has 1.1)\nos-dmidecode-1.0 < needs updating (index has 1.2)\n")
	if !packages[0].NeedsUpdate {
		t.Fatal("pkg should need update")
	}
	if packages[0].AvailableVersion != "1.1" {
		t.Fatalf("available=%q", packages[0].AvailableVersion)
	}
	if !packages[1].NeedsUpdate {
		t.Fatal("os-dmidecode should need update")
	}
	if packages[2].NeedsUpdate {
		t.Fatal("curl should not need update")
	}
}

func TestMarkAptUpdates(t *testing.T) {
	packages := parseDpkgQuery("bash\t5.2\ncurl\t8.0\n")
	packages = markAptUpdates(packages, "Listing...\nbash/stable 5.3 amd64 [upgradable from: 5.2]\n")
	if !packages[0].NeedsUpdate || packages[0].AvailableVersion != "5.3" {
		t.Fatalf("unexpected bash package: %+v", packages[0])
	}
	if packages[1].NeedsUpdate {
		t.Fatal("curl should not need update")
	}
}

func TestParseAptSourceRepos(t *testing.T) {
	repos := parseAptSourceRepos("# comment\ndeb https://deb.debian.org/debian bookworm main\ndeb http://mirror.local/debian bookworm main\n")
	if len(repos) != 2 {
		t.Fatalf("len=%d", len(repos))
	}
	if !repos[0].Secure || repos[1].Secure {
		t.Fatalf("unexpected secure flags: %+v", repos)
	}
}
