#!/bin/bash
# desc: check_mpic.sh のテスト。模擬 dig (tests/mock/dig) とテスト用データを使い、ネットワークに接続せずに実行する
#
# 使い方: tests/run_tests.sh
# 失敗したテストが1件でもあれば終了コード 1 を返す

TESTS_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$TESTS_DIR")"
SCRIPT="$ROOT_DIR/check_mpic.sh"

export PATH="$TESTS_DIR/mock:$PATH"
export MOCK_DNS_ZONE="$TESTS_DIR/fixtures/zone.txt"
export CHECK_MPIC_PSL_FILE="$TESTS_DIR/fixtures/public_suffix_list.dat"

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

PASSED=0
FAILED=0

pass() {
    PASSED=$((PASSED + 1))
    echo "  ok   $1"
}

fail() {
    FAILED=$((FAILED + 1))
    echo "  NG   $1"
    shift
    local line
    for line in "$@"; do
        echo "       $line"
    done
}

assert_eq() {
    local name=$1 expected=$2 actual=$3
    if [ "$expected" == "$actual" ]; then
        pass "$name"
    else
        fail "$name" "期待: $expected" "結果: $actual"
    fi
}

assert_contains() {
    local name=$1 needle=$2 haystack=$3
    if [[ "$haystack" == *"$needle"* ]]; then
        pass "$name"
    else
        fail "$name" "含まれるべき文字列: $needle" "出力:" "$haystack"
    fi
}

assert_not_contains() {
    local name=$1 needle=$2 haystack=$3
    if [[ "$haystack" != *"$needle"* ]]; then
        pass "$name"
    else
        fail "$name" "含まれてはいけない文字列: $needle" "出力:" "$haystack"
    fi
}

# スクリプトを実行し、標準出力と標準エラー出力をまとめて返す。終了コードは LAST_STATUS に入れる
run_script() {
    RUN_OUTPUT=$("$SCRIPT" "$@" 2>&1)
    LAST_STATUS=$?
}

# -q で1件確認し、CSR / ACME の判定記号を確かめる (⚠️ は後ろの空白を含めずに比べる)
assert_judgement() {
    local fqdn=$1 csr=$2 acme=$3
    run_script -q "$fqdn"
    assert_contains "$fqdn: CSR $csr" "CSR: $csr" "$RUN_OUTPUT"
    assert_contains "$fqdn: ACME $acme" "ACME: $acme" "$RUN_OUTPUT"
}

# ---------------------------------------------------------------------------
# 単体テスト: 関数を直接呼び出す
# ---------------------------------------------------------------------------
# shellcheck source-path=SCRIPTDIR source=../check_mpic.sh
source "$SCRIPT"

echo "■ get_etld_plus_one"
assert_eq "サブドメイン" "alpha.ac.jp" "$(get_etld_plus_one www.alpha.ac.jp "$PSL_FILE")"
assert_eq "eTLD+1 そのもの" "alpha.ac.jp" "$(get_etld_plus_one alpha.ac.jp "$PSL_FILE")"
assert_eq "1段の公開サフィックス" "example.com" "$(get_etld_plus_one a.b.example.com "$PSL_FILE")"
assert_eq "ワイルドカードのルール" "a.b.kawasaki.jp" "$(get_etld_plus_one x.a.b.kawasaki.jp "$PSL_FILE")"
assert_eq "例外のルール" "city.kawasaki.jp" "$(get_etld_plus_one www.city.kawasaki.jp "$PSL_FILE")"

echo "■ caa_denial_reason"
check_caa() {
    local expected=$1 records=$2 reason result
    reason=$(caa_denial_reason "$records")
    if [ -z "$reason" ]; then result="許可"; else result="不許可"; fi
    assert_eq "$expected: $records" "$expected" "$result"
}
check_caa "許可" '0 issue "secomtrust.net"'
check_caa "許可" '0 issue "SecomTrust.NET"'
check_caa "許可" '0 ISSUE "secomtrust.net"'
check_caa "許可" '0 issue "secomtrust.net; accounturi=https://example/acct/1"'
check_caa "許可" '0 issue "letsencrypt.org",0 issue "secomtrust.net"'
check_caa "許可" '0 issuewild "letsencrypt.org"'
check_caa "許可" '0 iodef "mailto:a@example.ac.jp"'
check_caa "許可" '0 futuretag "x",0 issue "secomtrust.net"'
check_caa "許可" '128 issue "secomtrust.net"'
check_caa "許可" '0 contactemail "a@example.ac.jp",0 issue "secomtrust.net"'
check_caa "不許可" '0 iodef "mailto:sec@secomtrust.net",0 issue "letsencrypt.org"'
check_caa "不許可" '0 issue "letsencrypt.org",0 issuewild "secomtrust.net"'
check_caa "不許可" '0 issue ";"'
check_caa "不許可" '0 issue "secomtrust.net.evil.example"'
check_caa "不許可" '128 futuretag "x",0 issue "secomtrust.net"'
assert_contains "不許可の理由に許可されているCAを示す" "letsencrypt.org" "$(caa_denial_reason '0 issue "letsencrypt.org"')"

echo "■ caa_parameter_effects"
check_effects() {
    local name=$1 records=$2 expected=$3
    assert_eq "$name" "$expected" "$(caa_parameter_effects "$records" | grep -v '^params=' | tr '\n' ' ' | sed 's/ $//')"
}
check_effects "パラメータなし" '0 issue "secomtrust.net"' \
    "has_params=0 acme_ok=1 acme_methods=all acme_allowed=dns-01,http-01 acme_tbr_only=0 acme_acct= csr_ok=1"
check_effects "ACMEの方式を含まない validationmethods" '0 issue "secomtrust.net; validationmethods=ca-tbr-4"' \
    "has_params=1 acme_ok=0 acme_methods= acme_allowed= acme_tbr_only=0 acme_acct= csr_ok=0"
check_effects "ACMEの方式を含む validationmethods" '0 issue "secomtrust.net; validationmethods=dns-01,http-01"' \
    "has_params=1 acme_ok=1 acme_methods=dns-01,http-01 acme_allowed=dns-01,http-01 acme_tbr_only=0 acme_acct= csr_ok=0"
check_effects "ca-tbr-N の形のACMEの方式" '0 issue "secomtrust.net; validationmethods=ca-tbr-7,ca-tbr-19"' \
    "has_params=1 acme_ok=1 acme_methods=ca-tbr-7,ca-tbr-19 acme_allowed=dns-01,http-01 acme_tbr_only=1 acme_acct= csr_ok=0"
check_effects "accounturi" '0 issue "secomtrust.net; accounturi=https://acme.example/acct/1"' \
    "has_params=1 acme_ok=1 acme_methods=all acme_allowed=dns-01,http-01 acme_tbr_only=0 acme_acct=https://acme.example/acct/1 csr_ok=0"
check_effects "パラメータなしの issue があれば制限なし" '0 issue "secomtrust.net; accounturi=https://acme.example/acct/1",0 issue "secomtrust.net"' \
    "has_params=1 acme_ok=1 acme_methods=all acme_allowed=dns-01,http-01 acme_tbr_only=0 acme_acct= csr_ok=1"
check_effects "大文字小文字を区別しない" '0 ISSUE "SecomTrust.net; VALIDATIONMETHODS=DNS-01"' \
    "has_params=1 acme_ok=1 acme_methods=dns-01 acme_allowed=dns-01 acme_tbr_only=0 acme_acct= csr_ok=0"
check_effects "ほかのCAのパラメータは無視" '0 issue "letsencrypt.org; accounturi=https://acme.example/acct/9",0 issue "secomtrust.net"' \
    "has_params=0 acme_ok=1 acme_methods=all acme_allowed=dns-01,http-01 acme_tbr_only=0 acme_acct= csr_ok=1"
check_effects "1つのレコードに両方のパラメータ" '0 issue "secomtrust.net; validationmethods=http-01; accounturi=acct:x@secomtrust.net"' \
    "has_params=1 acme_ok=1 acme_methods=http-01 acme_allowed=http-01 acme_tbr_only=0 acme_acct=acct:x@secomtrust.net csr_ok=0"
check_effects "tls-alpn-01 だけはUPKIのACMEで使えない" '0 issue "secomtrust.net; validationmethods=tls-alpn-01"' \
    "has_params=1 acme_ok=0 acme_methods= acme_allowed= acme_tbr_only=0 acme_acct= csr_ok=0"
check_effects "ca-tbr-20 (tls-alpn-01) もUPKIのACMEで使えない" '0 issue "secomtrust.net; validationmethods=ca-tbr-20"' \
    "has_params=1 acme_ok=0 acme_methods= acme_allowed= acme_tbr_only=0 acme_acct= csr_ok=0"
check_effects "tls-alpn-01 と並んだ http-01 は使える" '0 issue "secomtrust.net; validationmethods=tls-alpn-01,http-01"' \
    "has_params=1 acme_ok=1 acme_methods=http-01 acme_allowed=http-01 acme_tbr_only=0 acme_acct= csr_ok=0"
assert_eq "表示用のパラメータ" "validationmethods=http-01; accounturi=acct:x@secomtrust.net" \
    "$(kv_get "$(caa_parameter_effects '0 issue "secomtrust.net; validationmethods=http-01; accounturi=acct:x@secomtrust.net"')" params)"

echo "■ is_valid_hostname"
for h in www.example.ac.jp a-b.example.jp xn--eckwd4c7c.jp; do
    if is_valid_hostname "$h"; then pass "有効: $h"; else fail "有効: $h"; fi
done
for h in "*.example.ac.jp" "https://www.example.ac.jp/" "example" "-a.example.jp" "a_b.example.jp" ""; do
    if is_valid_hostname "$h"; then fail "無効: $h"; else pass "無効: $h"; fi
done

echo "■ worse_state"
assert_eq "問題なし + 条件付き" "2" "$(worse_state 1 2)"
assert_eq "条件付き + 発行できない" "0" "$(worse_state 2 0)"
assert_eq "問題なし + 問題なし" "1" "$(worse_state 1 1)"

echo "■ dig_cached"
# 本物の dig の代わりに、呼ばれた回数を数える関数を使う
dig() {
    echo x >> "$WORK_DIR/dig_calls"
    echo "answer for $*"
    return 9
}
DIG_CACHE_DIR="$WORK_DIR/dig_cache"
mkdir -p "$DIG_CACHE_DIR"
first=$(dig_cached CAA www.alpha.ac.jp @8.8.8.8 +short)
second=$(dig_cached +short @8.8.8.8 www.alpha.ac.jp CAA)
dig_cached CAA www.alpha.ac.jp @8.8.8.8 +short > /dev/null
rc=$?
dig_cached CAA www.alpha.ac.jp @1.1.1.1 +short > /dev/null
assert_eq "引数の順序が違っても同じ結果を返す" "$first" "$second"
assert_eq "終了コードも使い回す" "9" "$rc"
assert_eq "同じ問い合わせは1回だけ実行する" "2" "$(wc -l < "$WORK_DIR/dig_calls" | tr -d ' ')"
unset -f dig
DIG_CACHE_DIR=""

echo "■ dns_status / dns_records"
DNS_OUT=$(dns_query A www.echo.ac.jp "")
assert_eq "ステータス" "NOERROR" "$(dns_status "$DNS_OUT")"
assert_eq "応答がなければ TIMEOUT_OR_ERROR" "TIMEOUT_OR_ERROR" "$(dns_status ";; connection timed out; no servers could be reached")"
assert_eq "CNAMEの参照先のレコードも含む" "198.51.100.3" "$(dns_records "$DNS_OUT" A)"
assert_eq "所有者名で絞る" "echo-host.net." "$(dns_records "$DNS_OUT" CNAME WWW.Echo.ac.jp.)"
assert_eq "所有者名が違えば出さない" "" "$(dns_records "$DNS_OUT" A www.echo.ac.jp)"
assert_eq "eTLD+1 から下へ並べる" "alpha.ac.jp ok.alpha.ac.jp x.ok.alpha.ac.jp" "$(names_from_etld1 x.ok.alpha.ac.jp alpha.ac.jp | tr '\n' ' ' | sed 's/ $//')"
assert_eq "TLDまで並べる" "ok.alpha.ac.jp alpha.ac.jp ac.jp jp" "$(names_to_tld ok.alpha.ac.jp | tr '\n' ' ' | sed 's/ $//')"

echo "■ find_relevant_caa"
assert_eq "親ドメインのCAA" 'alpha.ac.jp|0 issue "secomtrust.net"' "$(find_relevant_caa ok.alpha.ac.jp "")"
assert_eq "自身のCAAが優先" 'own.bravo.ac.jp|0 issue "secomtrust.net"' "$(find_relevant_caa own.bravo.ac.jp "")"
assert_eq "CNAME先の親ではなく元のドメインの親へ遡る" 'delta.ac.jp|0 issue "letsencrypt.org"' "$(find_relevant_caa www.delta.ac.jp "")"
assert_eq "CNAME先自身のCAA" 'www.foxtrot.ac.jp(CNAME先: foxtrot-host.net)|0 issue "letsencrypt.org"' "$(find_relevant_caa www.foxtrot.ac.jp "")"
assert_eq "CAAがどこにもない" '|' "$(find_relevant_caa plain.hotel.ac.jp "")"
assert_eq "DNS拠点ごとに異なるCAA" 'split.alpha.ac.jp|0 issue "letsencrypt.org"' "$(find_relevant_caa split.alpha.ac.jp 1.1.1.1)"
assert_eq "上位ドメインのSERVFAILで探索を打ち切る" '!papa.ac.jp|SERVFAIL' "$(find_relevant_caa www.papa.ac.jp "")"
assert_eq "タイムアウトで探索を打ち切る" '!slow.alpha.ac.jp|TIMEOUT_OR_ERROR' "$(find_relevant_caa slow.alpha.ac.jp 1.1.1.1)"

echo "■ collect_auth_info"
collect_auth_info ok.alpha.ac.jp
assert_eq "ゾーン(親ドメインのNS)" "alpha.ac.jp" "$AUTH_ZONE"
assert_eq "権威DNSサーバー" "ns1.dns-provider.net (192.0.2.53)|ns2.dns-provider.net (192.0.2.54)" "$(IFS='|'; echo "${AUTH_SERVERS[*]}")"
assert_eq "ステータス" "NOERROR NOERROR" "${AUTH_STATUS[*]}"
assert_eq "SOAシリアル" "2026102501 2026102501" "${AUTH_SERIAL[*]}"
collect_auth_info www.kilo.ac.jp
assert_eq "サーバーごとのCAA" '0 issue "secomtrust.net"|0 issue "letsencrypt.org"' "$(IFS='|'; echo "${AUTH_CAA[*]}")"
collect_auth_info www.delta.ac.jp
assert_eq "CNAMEはサーバー自身の応答から取る" "edge.cdn-delta.net edge.cdn-delta.net" "${AUTH_CNAME[*]}"
assert_eq "CNAMEのノードではCAAなし" "|" "$(IFS='|'; echo "${AUTH_CAA[*]}")"
collect_auth_info www.mike.ac.jp
assert_eq "応答しない・拒否するサーバー" "NOERROR TIMEOUT_OR_ERROR REFUSED" "${AUTH_STATUS[*]}"
assert_eq "IPv4アドレスのないNS" "ns6.mike-dns.net" "${AUTH_NO_V4[*]}"
collect_auth_info plain.hotel.ac.jp
assert_eq "NSが見つからない" "" "$AUTH_ZONE"
collect_auth_info www.quebec.co.jp
assert_eq "親ゾーンの委任情報からゾーンを特定" "quebec.co.jp" "$AUTH_ZONE"
assert_eq "委任情報を取得した親ゾーン" "co.jp" "$AUTH_SOURCE"
assert_eq "グルーのアドレスで問い合わせる" "ns1.quebec.co.jp (192.0.2.101)|ns2.quebec.co.jp (192.0.2.102)" "$(IFS='|'; echo "${AUTH_SERVERS[*]}")"
assert_eq "親ゾーンのサーバーは応答" "1" "$AUTH_PARENT_REACHED"
if auth_all_unresponsive; then pass "どの権威DNSサーバーも応答しない"; else fail "どの権威DNSサーバーも応答しない"; fi
collect_auth_info www.mike.ac.jp
if auth_all_unresponsive; then fail "一部が応答すれば全滅としない"; else pass "一部が応答すれば全滅としない"; fi
assert_eq "応答があれば親ゾーンに問い合わせない" "" "$AUTH_PARENT_REACHED"

echo "■ parse_tsv"
# UPKIの申請TSVと同じ Shift-JIS / CR+LF / 13列のファイルを作る
make_tsv() {
    local out=$1
    shift
    local row
    for row in "$@"; do
        printf '%s\r\n' "$row"
    done | iconv -f UTF-8 -t SHIFT_JIS > "$out"
}
T=$'\t'
DN="CN=ok.alpha.ac.jp,O=Example University,L=Chiyoda-ku,ST=Tokyo,C=JP"
TSV="$WORK_DIR/sample.tsv"
make_tsv "$TSV" \
    "$DN${T}3${T}${T}${T}${T}${T}MIIBdummy${T}国立　太郎${T}情報基盤センター${T}taro@alpha.ac.jp${T}ok.alpha.ac.jp${T}nginx1.24${T}dNSName=www.alpha.ac.jp,dNSName=WWW.alpha.ac.jp,dNSName=missing.alpha.ac.jp" \
    "$DN${T}11${T}${T}${T}${T}${T}${T}情報　花子${T}情報基盤センター${T}hanako@alpha.ac.jp${T}Www.Alpha.Ac.Jp${T}apache2.4${T}" \
    "$DN${T}${T}${T}0123ABCD${T}4${T}${T}${T}${T}${T}taro@alpha.ac.jp" \
    "" \
    "$DN${T}3${T}${T}${T}${T}${T}CSR${T}名${T}所属${T}a@b${T}ok.alpha.ac.jp${T}nginx${T}dNSName=*.alpha.ac.jp,www2.alpha.ac.jp,"

ROW_LINES=()
ROW_CNS=()
ROW_HOSTS=()
PARSE_OUTPUT=$(parse_tsv "$TSV")
parse_tsv "$TSV" > /dev/null
assert_eq "対象の行番号" "1 2 5" "${ROW_LINES[*]}"
assert_eq "11列目を含め重複を除いたホスト名" "ok.alpha.ac.jp www.alpha.ac.jp missing.alpha.ac.jp" "${ROW_HOSTS[0]}"
assert_eq "dNSNameなしの行は11列目のみ(小文字にそろえる)" "www.alpha.ac.jp" "${ROW_HOSTS[1]}"
assert_eq "形式不正の要素は除外" "ok.alpha.ac.jp" "${ROW_HOSTS[2]}"
assert_contains "失効申請の行を対象外にする" "行3: 利用管理者FQDN(11列目)・dNSName(13列目)が空のため対象外" "$PARSE_OUTPUT"
assert_contains "末尾のカンマを警告" "行5: dNSName(13列目)の末尾に「,」があります" "$PARSE_OUTPUT"
assert_contains "ワイルドカードを警告(全角文字直前の変数が文字化けしない)" "ホスト名「*.alpha.ac.jp」は使用できない形式" "$PARSE_OUTPUT"
assert_contains "dNSName= のない要素を警告" "要素「www2.alpha.ac.jp」が「dNSName=ホスト名」の形式ではない" "$PARSE_OUTPUT"

# ---------------------------------------------------------------------------
# 結合テスト: スクリプトをコマンドとして実行する
# ---------------------------------------------------------------------------
echo "■ 判定結果 (-q)"
assert_judgement ok.alpha.ac.jp "✅" "✅"
assert_judgement plain.hotel.ac.jp "✅" "✅"
assert_judgement own.bravo.ac.jp "✅" "✅"
assert_judgement www.echo.ac.jp "✅" "✅"
assert_judgement www.bravo.ac.jp "❌" "❌"
assert_judgement iodef.charlie.ac.jp "❌" "❌"
assert_judgement wild.charlie.ac.jp "❌" "❌"
assert_judgement www.delta.ac.jp "❌" "❌"
assert_judgement www.foxtrot.ac.jp "❌" "❌"
assert_judgement missing.alpha.ac.jp "⚠️" "❌"
assert_judgement internal.alpha.ac.jp "⚠️" "❌"
assert_judgement geo.alpha.ac.jp "❌" "❌"
assert_judgement slow.alpha.ac.jp "❌" "❌"
assert_judgement split.alpha.ac.jp "❌" "❌"

echo "■ デフォルトDNSだけの違い (判定はパブリックDNSで行う)"
assert_judgement intra-cname.alpha.ac.jp "✅" "✅"
run_script -q intra-cname.alpha.ac.jp
assert_contains "デフォルトDNSだけのCNAMEは注意" "← 注意: デフォルトDNSとパブリックDNSでCNAMEレコードが一致しません。" "$RUN_OUTPUT"
assert_judgement intra-missing.alpha.ac.jp "✅" "✅"
run_script -q intra-missing.alpha.ac.jp
assert_contains "デフォルトDNSだけのNXDOMAINは注意" "← 注意: デフォルトDNSでだけNXDOMAIN（存在しない）となりました。" "$RUN_OUTPUT"
assert_judgement intra-caa.alpha.ac.jp "✅" "✅"
run_script intra-caa.alpha.ac.jp
assert_contains "デフォルトDNSだけのCAAは注意" "・デフォルトDNSとパブリックDNSでCAAレコードが一致しません。" "$RUN_OUTPUT"
assert_not_contains "デフォルトDNSだけのCAAを重ねて指摘しない" "・デフォルトDNSで実効的に適用されるCAAレコード" "$RUN_OUTPUT"
assert_judgement nx-deftimeout.alpha.ac.jp "⚠️" "❌"
run_script -q nx-deftimeout.alpha.ac.jp
assert_contains "デフォルトDNSが失敗してもパブリックDNSのNXDOMAINで判定" "← パブリックDNS (8.8.8.8 / 1.1.1.1) でNXDOMAIN（存在しない）となりました。" "$RUN_OUTPUT"
assert_judgement nx-split.alpha.ac.jp "❌" "❌"
run_script -q nx-split.alpha.ac.jp
assert_contains "パブリックDNSの間でNXDOMAINと分かれる" "← パブリックDNSの間で、NXDOMAIN（存在しない）と解決できる結果に分かれました" "$RUN_OUTPUT"
assert_judgement caa-split.alpha.ac.jp "❌" "❌"
run_script -q caa-split.alpha.ac.jp
assert_contains "デフォルトDNSが失敗してもパブリックDNSのCAAを比べる" "← 取得されたCAAレコードがパブリックDNSの間で一致しませんでした。" "$RUN_OUTPUT"
assert_judgement refused.alpha.ac.jp "❌" "❌"
run_script -q refused.alpha.ac.jp
assert_contains "REFUSEDも名前解決の失敗" "8.8.8.8=REFUSED, 1.1.1.1=REFUSED" "$RUN_OUTPUT"

echo "■ 問い合わせの先読みと使い回し"
# 先読み(並列)と、その後の順の処理とで、同じ問い合わせを2回実行しないこと (問い合わせの形がそろっていること)
for host in ok.alpha.ac.jp www.delta.ac.jp www.kilo.ac.jp www.quebec.co.jp acme-delegated.alpha.ac.jp; do
    for opt in "" -q; do
        rm -f "$WORK_DIR/dns.log"
        MOCK_DNS_LOG="$WORK_DIR/dns.log" "$SCRIPT" $opt "$host" > /dev/null 2>&1
        assert_eq "同じ問い合わせは1回だけ: $host ${opt:-(詳細表示)}" "" "$(sort "$WORK_DIR/dns.log" | uniq -d)"
    done
done
run_script www.quebec.co.jp
assert_contains "対象FQDNが引けなければACMEの確認を省く" "www.quebec.co.jp 自体の名前解決にパブリックDNSで失敗したため、dns-01 / http-01 の確認は省略しました (8.8.8.8=SERVFAIL, 1.1.1.1=SERVFAIL)。" "$RUN_OUTPUT"
assert_not_contains "省いたときは _acme-challenge を表示しない" "--- dns-01 (_acme-challenge.www.quebec.co.jp) ---" "$RUN_OUTPUT"
run_script refused.alpha.ac.jp
assert_contains "REFUSEDはステータスを表示" "名前解決ができません (status: REFUSED)。" "$RUN_OUTPUT"
assert_not_contains "REFUSEDをCNAMEの先と誤表示しない" "!REFUSED" "$RUN_OUTPUT"

echo "■ 判定結果の見出し (発行方式別の見通しと食い違わない)"
run_script ok.alpha.ac.jp
assert_contains "両方とも発行できれば ✅" "判定結果: ✅ パスする可能性が高いです。" "$RUN_OUTPUT"
run_script www.bravo.ac.jp
assert_contains "両方とも発行できなければ ❌" "判定結果: ❌ パスしない（エラーになる）可能性が高いです。" "$RUN_OUTPUT"
run_script acme-broken.alpha.ac.jp
assert_contains "ACMEだけ発行できなければ ⚠️" "判定結果: ⚠️  発行方式によって結果が異なります (CSR申請: ✅ / ACME発行: ❌)。" "$RUN_OUTPUT"
assert_not_contains "ACMEだけ発行できなくても ❌ にしない" "判定結果: ❌" "$RUN_OUTPUT"
assert_contains "原因は表示する" "・UPKIのACMEで使える検証方式 (dns-01 / http-01) のどちらでも、ACMEで発行できません。" "$RUN_OUTPUT"
run_script missing.alpha.ac.jp
assert_contains "NXDOMAIN (CSR要確認・ACME不可) は ⚠️" "判定結果: ⚠️  発行方式によって結果が異なります (CSR申請: ⚠️  / ACME発行: ❌)。" "$RUN_OUTPUT"
CHECK_MPIC_TODAY="2027-03-15" run_script vm-acme.alpha.ac.jp
assert_contains "CSRだけ要確認なら ✅ にしない" "判定結果: ⚠️  発行方式によって結果が異なります (CSR申請: ⚠️  / ACME発行: ✅)。" "$RUN_OUTPUT"

echo "■ 判定理由"
run_script -q missing.alpha.ac.jp
assert_contains "NXDOMAIN" "すべてのDNSサーバーでNXDOMAIN" "$RUN_OUTPUT"
run_script -q internal.alpha.ac.jp
assert_contains "スプリットホライズン" "デフォルトDNSでは解決できますが、パブリックDNSでNXDOMAIN" "$RUN_OUTPUT"
run_script -q geo.alpha.ac.jp
assert_contains "パブリックDNSでのSERVFAIL" "8.8.8.8=SERVFAIL" "$RUN_OUTPUT"
run_script -q slow.alpha.ac.jp
assert_contains "パブリックDNSでのタイムアウト" "1.1.1.1=TIMEOUT_OR_ERROR" "$RUN_OUTPUT"
run_script -q split.alpha.ac.jp
assert_contains "DNS拠点間のCAAの不一致" "CAAレコードがパブリックDNSの間で一致しませんでした" "$RUN_OUTPUT"
run_script -q www.delta.ac.jp
assert_contains "元のドメインの親のCAAで判定" "(delta.ac.jp: 0 issue \"letsencrypt.org\")" "$RUN_OUTPUT"
run_script -q www.foxtrot.ac.jp
assert_contains "CNAME先のCAAであることを表示" "www.foxtrot.ac.jp(CNAME先: foxtrot-host.net)" "$RUN_OUTPUT"
# [理由] の行は -q のまとめには出ず、詳細表示にだけ出る
run_script iodef.charlie.ac.jp
assert_contains "iodefは許可にならない" "[理由] issueで許可されているCA(letsencrypt.org)に secomtrust.net が含まれません" "$RUN_OUTPUT"

echo "■ 権威DNSサーバーでの確認"
assert_judgement www.kilo.ac.jp "❌" "❌"
run_script -q www.kilo.ac.jp
assert_contains "権威DNSサーバー間の不一致" "権威DNSサーバー間で応答(ステータス、CAA、CNAME)が一致しませんでした。(ゾーン: kilo.ac.jp)" "$RUN_OUTPUT"
run_script www.kilo.ac.jp
assert_contains "不一致のサーバーごとの応答" "ns2.kilo-dns.net (192.0.2.62): status=NOERROR, CAA='0 issue \"letsencrypt.org\"'" "$RUN_OUTPUT"
assert_judgement www.lima.ac.jp "✅" "✅"
run_script -q www.lima.ac.jp
assert_contains "SOAシリアルの不一致は注意" "← 注意: 権威DNSサーバー間でSOAシリアルが一致しません。(ゾーン: lima.ac.jp)" "$RUN_OUTPUT"
assert_judgement www.mike.ac.jp "✅" "✅"
run_script www.mike.ac.jp
assert_contains "注意の見出し" "【注意】" "$RUN_OUTPUT"
assert_contains "応答しないサーバー" "ns2.mike-dns.net (192.0.2.82): TIMEOUT_OR_ERROR" "$RUN_OUTPUT"
assert_contains "拒否するサーバー" "ns3.mike-dns.net (192.0.2.83): REFUSED" "$RUN_OUTPUT"
assert_contains "IPv4アドレスのないサーバー" "IPv4アドレスが見つからない権威DNSサーバーがあります (ns6.mike-dns.net)" "$RUN_OUTPUT"
assert_contains "詳細表示の節" "権威DNSサーバーでの確認 (再帰なしで直接問い合わせ)" "$RUN_OUTPUT"
assert_contains "詳細表示のサーバーごとの応答" "--- ns1.mike-dns.net (192.0.2.81) ---" "$RUN_OUTPUT"
run_script -q www.november.ac.jp
assert_contains "どの権威DNSサーバーにも問い合わせできない" "← 注意: 権威DNSサーバーのどれにも直接問い合わせできませんでした" "$RUN_OUTPUT"
assert_judgement www.quebec.co.jp "❌" "❌"
run_script -q www.quebec.co.jp
assert_contains "まとめにパブリックDNSでの失敗と表示" "← パブリックDNS (8.8.8.8 または 1.1.1.1) で名前解決に失敗しました" "$RUN_OUTPUT"
assert_not_contains "どれにも問い合わせできない注意を重ねて出さない" "直接問い合わせできませんでした" "$RUN_OUTPUT"
run_script www.quebec.co.jp
assert_contains "権威DNSサーバーの全滅を原因と推測" "[原因推測] ゾーン (quebec.co.jp) の権威DNSサーバーがどれも応答しません (ns1.quebec.co.jp (192.0.2.101), ns2.quebec.co.jp (192.0.2.102))" "$RUN_OUTPUT"
assert_contains "この端末の通信の制限ではない" "この端末の通信の制限ではありません" "$RUN_OUTPUT"
assert_not_contains "GeoIPと推測しない" "GeoIPブロッキング）が行われている可能性が高いです" "$RUN_OUTPUT"
assert_not_contains "+cd での確認をしない" "DNSSECの検証失敗ではありませんでした" "$RUN_OUTPUT"
assert_contains "委任情報から特定したことを表示" "親ゾーン (co.jp) の権威DNSサーバーに登録された委任情報から特定しました" "$RUN_OUTPUT"
assert_judgement www.romeo.co.jp "✅" "✅"
run_script -q www.romeo.co.jp
assert_contains "キャッシュで応答している可能性の注意" "← 注意: 権威DNSサーバーがどれも応答しませんでした。(ゾーン: romeo.co.jp)" "$RUN_OUTPUT"
run_script -q plain.hotel.ac.jp
assert_contains "NSを特定できない" "← 注意: 権威DNSサーバー(NSレコード)を特定できなかった" "$RUN_OUTPUT"
run_script -q ok.alpha.ac.jp
assert_not_contains "問題がなければ注意を出さない" "注意" "$RUN_OUTPUT"

echo "■ DNSSEC"
if is_dnssec_failure www.oscar.ac.jp 8.8.8.8; then pass "検証失敗のゾーンを判別"; else fail "検証失敗のゾーンを判別"; fi
if is_dnssec_failure geo.alpha.ac.jp 8.8.8.8; then fail "DNSSEC以外のSERVFAILは検証失敗としない"; else pass "DNSSEC以外のSERVFAILは検証失敗としない"; fi
assert_judgement www.oscar.ac.jp "❌" "❌"
run_script -q www.oscar.ac.jp
assert_contains "まとめに検証失敗と表示" "← DNSSECの検証に失敗したため、パブリックDNS (8.8.8.8 1.1.1.1) で名前解決できませんでした" "$RUN_OUTPUT"
assert_eq "検証失敗は終了コード 2" "2" "$LAST_STATUS"
run_script www.oscar.ac.jp
assert_contains "原因の推測" "署名の検証を省く(+cd)と解決できるため、DNSSECの署名に不備があります。" "$RUN_OUTPUT"
assert_contains "SC-085v2 への言及" "CAはDNSSECの検証が必須です(SC-085v2)" "$RUN_OUTPUT"
assert_not_contains "GeoIPと推測しない" "GeoIPブロッキング" "$RUN_OUTPUT"
assert_contains "リゾルバごとの確認でも検証失敗と表示" "署名の検証を省く(+cd)と解決できるため、DNSSECの検証失敗が原因です。" "$RUN_OUTPUT"
assert_contains "署名ありと表示" "DNSSEC: 署名あり" "$RUN_OUTPUT"
run_script geo.alpha.ac.jp
assert_contains "DNSSEC以外のSERVFAILはGeoIPと推測" "GeoIPブロッキング" "$RUN_OUTPUT"
assert_contains "+cd でも確認したことを示す" "DNSSECの検証失敗ではありませんでした" "$RUN_OUTPUT"
assert_not_contains "名前解決の失敗をCAAの問い合わせ失敗として重ねて指摘しない" "CAAレコードの問い合わせに失敗しました" "$RUN_OUTPUT"
assert_not_contains "DNSSEC以外のSERVFAILでは検証失敗と表示しない" "DNSSECの検証失敗が原因です" "$RUN_OUTPUT"
run_script www.bravo.ac.jp
assert_contains "署名なしと表示" "DNSSEC: 署名なし" "$RUN_OUTPUT"

echo "■ 実効CAAの探索中の問い合わせ失敗"
assert_judgement www.papa.ac.jp "❌" "❌"
run_script -q www.papa.ac.jp
assert_contains "まとめに問い合わせ失敗と表示" "← 実効CAAレコードの探索中に、CAAレコードの問い合わせに失敗しました (8.8.8.8: papa.ac.jp=SERVFAIL, 1.1.1.1: papa.ac.jp=SERVFAIL)" "$RUN_OUTPUT"
run_script www.papa.ac.jp
assert_contains "BR 3.2.2.8 への言及" "CAAの確認に失敗すると、CAは原則として発行できません(BR 3.2.2.8)" "$RUN_OUTPUT"

echo "■ CAAのパラメータ (施行日 2027-03-15 より前)"
export CHECK_MPIC_TODAY="2027-03-14"
assert_judgement vm-email.alpha.ac.jp "✅" "✅"
run_script -q vm-email.alpha.ac.jp
assert_eq "施行日前は注意だけ(終了コード 1)" "1" "$LAST_STATUS"
run_script vm-email.alpha.ac.jp
assert_contains "施行日以降にACMEで発行できなくなる" "2027-03-15以降、ACMEでは発行できなくなります。実効CAAレコードの validationmethods (validationmethods=ca-tbr-4)" "$RUN_OUTPUT"
assert_contains "施行日以降にCSR申請が制限される" "2027-03-15以降、CSR申請が実効CAAレコードのパラメータ (validationmethods=ca-tbr-4) で制限されます" "$RUN_OUTPUT"
assert_not_contains "施行日前はCSRを要確認にしない" "CSR申請  : ⚠️" "$RUN_OUTPUT"

echo "■ CAAのパラメータ (施行日 2027-03-15 以降)"
export CHECK_MPIC_TODAY="2027-03-15"
assert_judgement vm-email.alpha.ac.jp "⚠️" "❌"
run_script -q vm-email.alpha.ac.jp
assert_contains "ACMEの方式がない" "← 実効CAAレコードの validationmethods (validationmethods=ca-tbr-4) にUPKIのACMEで使える検証方式(dns-01 / http-01)が含まれないため、ACMEでは発行できません。" "$RUN_OUTPUT"
assert_eq "ACMEで発行できなければ終了コード 2" "2" "$LAST_STATUS"
run_script vm-email.alpha.ac.jp
assert_contains "CSRの見通しは要確認" "CSR申請  : ⚠️  実効CAAレコードのパラメータ(validationmethods=ca-tbr-4)でUPKIのCSR申請が許可されるか、UPKI/CAへの確認が必要です。" "$RUN_OUTPUT"
assert_contains "BRの規定を示す" "CAはvalidationmethodsの処理が必須です(BR 4.2.2.1.2、SC-098)" "$RUN_OUTPUT"

assert_judgement vm-acme.alpha.ac.jp "⚠️" "✅"
run_script vm-acme.alpha.ac.jp
assert_contains "ACMEで使える方式の注意" "ACMEで使える検証方式が validationmethods で限定されます (dns-01,http-01)" "$RUN_OUTPUT"
assert_eq "CSRが要確認なら終了コード 1" "1" "$LAST_STATUS"

assert_judgement vm-tbr.alpha.ac.jp "⚠️" "✅"
run_script vm-tbr.alpha.ac.jp
assert_contains "ca-tbr-N の書き方の注意" "ca-tbr-N の形で書かれています" "$RUN_OUTPUT"

assert_judgement acct.alpha.ac.jp "⚠️" "✅"
run_script acct.alpha.ac.jp
assert_contains "accounturi の注意" "ACMEでは accounturi で指定されたアカウント (https://acme.example/acct/123) からのみ発行できます" "$RUN_OUTPUT"
assert_contains "ACME以外の accounturi は判定できない" "ACME以外の申請での accounturi の形式は、このツールでは判定できない" "$RUN_OUTPUT"

assert_judgement acct-open.alpha.ac.jp "✅" "✅"
run_script -q acct-open.alpha.ac.jp
assert_eq "パラメータなしの issue があれば終了コード 0" "0" "$LAST_STATUS"
assert_not_contains "パラメータなしの issue があれば注意なし" "注意" "$RUN_OUTPUT"

run_script -q ok.alpha.ac.jp
assert_eq "パラメータのない通常のドメインは影響なし" "0" "$LAST_STATUS"
unset CHECK_MPIC_TODAY

echo "■ is_private_ip"
for a in 10.1.2.3 172.16.0.1 172.31.255.255 192.168.1.1 127.0.0.1 169.254.1.1 100.64.0.1 100.127.255.255 0.0.0.0 ::1 :: fc00::1 fd12::1 fe80::1 FE80::1; do
    if is_private_ip "$a"; then pass "接続できない: $a"; else fail "接続できない: $a"; fi
done
for a in 192.0.2.1 172.15.0.1 172.32.0.1 100.63.255.255 100.128.0.1 8.8.8.8 2001:db8::1 2606:4700::1; do
    if is_private_ip "$a"; then fail "接続できる: $a"; else pass "接続できる: $a"; fi
done

echo "■ ACME向けの事前確認"
assert_judgement acme-private.alpha.ac.jp "✅" "✅"
run_script acme-private.alpha.ac.jp
assert_contains "http-01 はプライベートアドレスだけなら使えない" "→ 使えません: アドレスがすべてプライベートアドレスのため、CAが接続できません (10.1.2.3)" "$RUN_OUTPUT"
assert_contains "dns-01 は使えるので ACME は可" "(使える検証方式: dns-01)" "$RUN_OUTPUT"
assert_contains "tls-alpn-01 はUPKIでは使えない" "--- tls-alpn-01 ---" "$RUN_OUTPUT"
assert_contains "tls-alpn-01 の表示" "→ UPKIのACMEでは使えません" "$RUN_OUTPUT"
run_script acme-noaddr.alpha.ac.jp
assert_contains "Aレコード・AAAAレコードがなければ http-01 は使えない" "→ 使えません: Aレコード・AAAAレコードがありません" "$RUN_OUTPUT"

assert_judgement acme-broken.alpha.ac.jp "✅" "❌"
run_script acme-broken.alpha.ac.jp
assert_contains "どちらの方式も使えなければACME不可" "UPKIのACMEで使える検証方式 (dns-01 / http-01) のどちらでも、ACMEで発行できません。" "$RUN_OUTPUT"
assert_contains "dns-01 が使えない理由" "dns-01: _acme-challenge.acme-broken.alpha.ac.jp の名前解決に失敗しました (8.8.8.8=SERVFAIL, 1.1.1.1=SERVFAIL)" "$RUN_OUTPUT"
assert_contains "http-01 が使えない理由" "http-01: アドレスがすべてプライベートアドレスのため、CAが接続できません (192.168.10.10)" "$RUN_OUTPUT"
assert_eq "ACMEが不可なら終了コード 2" "2" "$LAST_STATUS"

run_script -q acme-dangle.alpha.ac.jp
assert_contains "委任先が存在しない" "← 注意: _acme-challenge.acme-dangle.alpha.ac.jp のCNAMEの参照先 (gone.acme-dns.example) が存在しません (NXDOMAIN)。" "$RUN_OUTPUT"
assert_eq "委任先が存在しなければ終了コード 1" "1" "$LAST_STATUS"
run_script acme-delegated.alpha.ac.jp
assert_contains "委任のCNAMEを表示" "CNAME: abcd1234.auth.acme-dns.example" "$RUN_OUTPUT"
assert_not_contains "委任先があれば注意なし" "【注意】" "$RUN_OUTPUT"
run_script acme-txt.alpha.ac.jp
assert_contains "残っているTXTを表示" "TXT: \"old-token\"" "$RUN_OUTPUT"
assert_eq "残っているTXTは注意にしない" "0" "$LAST_STATUS"

run_script -q acme-v6.alpha.ac.jp
assert_eq "AAAAレコードは終了コードに影響しない" "0" "$LAST_STATUS"
assert_not_contains "AAAAレコードは注意にしない" "注意" "$RUN_OUTPUT"
run_script acme-v6.alpha.ac.jp
assert_contains "AAAAレコードは詳細表示で参考として表示" "(参考) AAAAレコードがあります。CAはIPv6で接続することがあるため" "$RUN_OUTPUT"
assert_contains "IPv6アドレスも接続できるアドレスに含める" "CAが接続できるアドレス: 192.0.2.40, 2001:db8::40" "$RUN_OUTPUT"
assert_not_contains "AAAAレコードは【注意】にしない" "【注意】" "$RUN_OUTPUT"
run_script ok.alpha.ac.jp
assert_not_contains "AAAAレコードがなければ参考表示もしない" "(参考) AAAA" "$RUN_OUTPUT"
run_script -q acme-mixed.alpha.ac.jp
assert_contains "プライベートアドレスの混在の注意" "← 注意: acme-mixed.alpha.ac.jp のアドレスにプライベートアドレス (172.16.0.41) が含まれています。" "$RUN_OUTPUT"
run_script -q --acme-method dns-01 acme-mixed.alpha.ac.jp
assert_eq "dns-01 を指定すれば http-01 の注意は出さない" "0" "$LAST_STATUS"

echo "■ --acme-method"
run_script -q --acme-method http-01 acme-private.alpha.ac.jp
assert_contains "http-01 を指定してプライベートアドレスだけなら不可" "← --acme-method で指定した検証方式 (http-01) では、ACMEで発行できません。" "$RUN_OUTPUT"
assert_eq "指定した方式で発行できなければ終了コード 2" "2" "$LAST_STATUS"
run_script -q --acme-method dns-01 acme-private.alpha.ac.jp
assert_eq "dns-01 を指定すれば可" "0" "$LAST_STATUS"
run_script --acme-method dns-01 acme-private.alpha.ac.jp
assert_contains "指定した方式を表示" "--acme-method で指定された検証方式: dns-01" "$RUN_OUTPUT"
run_script -q --acme-method dns-01 acme-dangle.alpha.ac.jp
assert_eq "dns-01 を指定すれば委任先の注意も出す" "1" "$LAST_STATUS"
run_script -q --acme-method http-01 acme-dangle.alpha.ac.jp
assert_eq "http-01 を指定すれば委任先の注意は出さない" "0" "$LAST_STATUS"
run_script -q --acme-method tls-alpn-01 ok.alpha.ac.jp
assert_eq "tls-alpn-01 はエラー(終了コード 3)" "3" "$LAST_STATUS"
assert_contains "tls-alpn-01 のエラーの説明" "tls-alpn-01 はUPKIのACMEでは使えません。" "$RUN_OUTPUT"
run_script -q --acme-method foo ok.alpha.ac.jp
assert_eq "不明な方式はエラー(終了コード 3)" "3" "$LAST_STATUS"
run_script -q --acme-method
assert_eq "方式の指定なしはエラー(終了コード 3)" "3" "$LAST_STATUS"

echo "■ ACME向けの事前確認とCAAのパラメータ"
export CHECK_MPIC_TODAY="2027-03-15"
assert_judgement vm-http-private.alpha.ac.jp "⚠️" "❌"
run_script vm-http-private.alpha.ac.jp
assert_contains "CAAで許可されていない方式" "dns-01: 実効CAAレコードの validationmethods で許可されていません" "$RUN_OUTPUT"
assert_contains "CAAで許可された方式が使えない" "http-01: アドレスがすべてプライベートアドレスのため、CAが接続できません (10.3.4.5)" "$RUN_OUTPUT"
assert_judgement vm-tlsalpn.alpha.ac.jp "⚠️" "❌"
run_script -q vm-tlsalpn.alpha.ac.jp
assert_contains "tls-alpn-01 だけのCAAはACME不可" "にUPKIのACMEで使える検証方式(dns-01 / http-01)が含まれないため、ACMEでは発行できません。" "$RUN_OUTPUT"
export CHECK_MPIC_TODAY="2027-03-14"
assert_judgement vm-http-private.alpha.ac.jp "✅" "✅"
run_script vm-http-private.alpha.ac.jp
assert_contains "施行日前はCAAの限定を判定に使わない" "(使える検証方式: dns-01)" "$RUN_OUTPUT"
unset CHECK_MPIC_TODAY

echo "■ resolve_path (readlink -f を使わないシンボリックリンクの解決)"
mkdir -p "$WORK_DIR/real" "$WORK_DIR/links"
touch "$WORK_DIR/real/script.sh"
ln -s ../real/script.sh "$WORK_DIR/links/relative"
ln -s "$WORK_DIR/links/relative" "$WORK_DIR/absolute"
REAL_PATH="$(cd "$WORK_DIR/real" && pwd)/script.sh"
assert_eq "リンクでないファイル" "$REAL_PATH" "$(resolve_path "$WORK_DIR/real/script.sh")"
assert_eq "相対パスのリンク" "$REAL_PATH" "$(resolve_path "$WORK_DIR/links/relative")"
assert_eq "絶対パスのリンクから相対パスのリンクへ(2段)" "$REAL_PATH" "$(resolve_path "$WORK_DIR/absolute")"

echo "■ Public Suffix List の取得と更新"
PSL_FIXTURE="$TESTS_DIR/fixtures/public_suffix_list.dat"
export MOCK_CURL_LOG="$WORK_DIR/curl.log"
# 実体のディレクトリに置いたPSLを使う(既定の場所の)構成を、作業用ディレクトリに作る
mkdir -p "$WORK_DIR/app" "$WORK_DIR/bin"
cp "$SCRIPT" "$WORK_DIR/app/check_mpic.sh"
cp "$PSL_FIXTURE" "$WORK_DIR/app/public_suffix_list.dat"
ln -s ../app/check_mpic.sh "$WORK_DIR/bin/check_mpic"
APP_PSL="$WORK_DIR/app/public_suffix_list.dat"
run_app() {
    RUN_OUTPUT=$(env -u CHECK_MPIC_PSL_FILE "$WORK_DIR/bin/check_mpic" "$@" 2>&1)
    LAST_STATUS=$?
}
curl_calls() {
    if [ -f "$MOCK_CURL_LOG" ]; then grep -c . "$MOCK_CURL_LOG"; else echo 0; fi
}

rm -f "$MOCK_CURL_LOG"
run_app -q ok.alpha.ac.jp
assert_eq "シンボリックリンク経由で実体の場所のPSLを使う" "0" "$LAST_STATUS"
assert_eq "新しいPSLは取り直さない" "0" "$(curl_calls)"

touch -t 202001010000 "$APP_PSL"
rm -f "$MOCK_CURL_LOG"
MOCK_CURL_SOURCE="$PSL_FIXTURE" run_app -q ok.alpha.ac.jp
assert_eq "古いPSLを自動で取り直す" "1" "$(curl_calls)"
assert_contains "取り直しのお知らせ" "を取り直します (30日より古いため)" "$RUN_OUTPUT"
assert_contains "更新のお知らせ" "Public Suffix List を更新しました。" "$RUN_OUTPUT"
assert_eq "取り直したあとも確認を続ける" "0" "$LAST_STATUS"
if is_older_than_days "$APP_PSL" 30; then fail "取り直したファイルは新しくなる"; else pass "取り直したファイルは新しくなる"; fi

touch -t 202001010000 "$APP_PSL"
MOCK_CURL_FAIL=1 MOCK_CURL_SOURCE="$PSL_FIXTURE" run_app -q ok.alpha.ac.jp
assert_contains "取り直しに失敗しても続ける" "取り直しに失敗しました。手元のリストで確認を続けます。" "$RUN_OUTPUT"
assert_eq "取り直しに失敗しても判定は変わらない" "0" "$LAST_STATUS"
assert_eq "失敗したときは元のファイルを残す" "$(cat "$PSL_FIXTURE")" "$(cat "$APP_PSL")"

echo "not a public suffix list" > "$WORK_DIR/bad.dat"
MOCK_CURL_SOURCE="$WORK_DIR/bad.dat" run_app -q ok.alpha.ac.jp
assert_eq "PSLでない内容では上書きしない" "$(cat "$PSL_FIXTURE")" "$(cat "$APP_PSL")"
assert_eq "一時ファイルを残さない" "0" "$(find "$WORK_DIR/app" -name '*.tmp.*' | grep -c .)"

# 環境変数 CHECK_MPIC_PSL_FILE で指定したファイル
cp "$PSL_FIXTURE" "$WORK_DIR/custom.dat"
touch -t 202001010000 "$WORK_DIR/custom.dat"
rm -f "$MOCK_CURL_LOG"
CHECK_MPIC_PSL_FILE="$WORK_DIR/custom.dat" MOCK_CURL_SOURCE="$PSL_FIXTURE" run_script -q ok.alpha.ac.jp
assert_eq "指定したファイルは古くても自動では取り直さない" "0" "$(curl_calls)"

CHECK_MPIC_PSL_FILE="$WORK_DIR/custom.dat" MOCK_CURL_SOURCE="$PSL_FIXTURE" run_script --update-psl
assert_eq "--update-psl だけなら取り直して終了(終了コード 0)" "0" "$LAST_STATUS"
assert_eq "--update-psl は指定したファイルでも取り直す" "1" "$(curl_calls)"
assert_contains "--update-psl のお知らせ" "を取り直します (--update-psl の指定)" "$RUN_OUTPUT"
assert_not_contains "--update-psl だけなら確認はしない" "MPIC判定結果" "$RUN_OUTPUT"

CHECK_MPIC_PSL_FILE="$WORK_DIR/custom.dat" MOCK_CURL_FAIL=1 run_script --update-psl
assert_eq "--update-psl だけで失敗したら終了コード 3" "3" "$LAST_STATUS"

CHECK_MPIC_PSL_FILE="$WORK_DIR/custom.dat" MOCK_CURL_FAIL=1 run_script -q --update-psl ok.alpha.ac.jp
assert_eq "--update-psl とFQDNなら失敗しても確認を続ける" "0" "$LAST_STATUS"

CHECK_MPIC_PSL_FILE="$WORK_DIR/none.dat" MOCK_CURL_SOURCE="$PSL_FIXTURE" run_script -q ok.alpha.ac.jp
assert_eq "PSLがなければ取得して確認する" "0" "$LAST_STATUS"
if [ -f "$WORK_DIR/none.dat" ]; then pass "取得したPSLを保存する"; else fail "取得したPSLを保存する"; fi
CHECK_MPIC_PSL_FILE="$WORK_DIR/none2.dat" MOCK_CURL_FAIL=1 run_script -q ok.alpha.ac.jp
assert_eq "PSLがなく取得もできなければ終了コード 3" "3" "$LAST_STATUS"
unset MOCK_CURL_LOG

echo "■ 終了コード"
run_script -q ok.alpha.ac.jp
assert_eq "問題なし → 0" "0" "$LAST_STATUS"
run_script ok.alpha.ac.jp
assert_eq "詳細表示でも同じ" "0" "$LAST_STATUS"
run_script -q www.lima.ac.jp
assert_eq "注意あり → 1" "1" "$LAST_STATUS"
run_script -q www.kilo.ac.jp
assert_eq "発行できない → 2" "2" "$LAST_STATUS"
run_script -q missing.alpha.ac.jp
assert_eq "CSRは条件付きでもACMEが発行できない → 2" "2" "$LAST_STATUS"

echo "■ 入力の正規化"
run_script -q OK.ALPHA.AC.JP.
assert_contains "末尾のドットと大文字" "ok.alpha.ac.jp" "$RUN_OUTPUT"
assert_contains "末尾のドットと大文字の判定" "CSR: ✅" "$RUN_OUTPUT"
run_script -q https://ok.alpha.ac.jp/
assert_eq "URLはエラー(終了コード)" "3" "$LAST_STATUS"
assert_contains "URLはエラー(メッセージ)" "FQDNの形式ではありません" "$RUN_OUTPUT"

echo "■ 詳細表示 (-q なし)"
run_script www.foxtrot.ac.jp
assert_contains "MPIC判定結果の見出し" "【MPIC判定結果】" "$RUN_OUTPUT"
assert_contains "発行方式別の見通し" "【発行方式別の見通し】" "$RUN_OUTPUT"
assert_contains "CNAMEのノードではCNAME先にあると表示" "CAAレコードはCNAMEの先 (foxtrot-host.net) にあります (www.foxtrot.ac.jp)" "$RUN_OUTPUT"
assert_contains "CNAME先のCAAを表示" "CNAME先のCAAレコード (foxtrot-host.net):" "$RUN_OUTPUT"
assert_contains "eTLD+1まで遡る" "頂点ドメイン(eTLD+1: foxtrot.ac.jp) に到達しました" "$RUN_OUTPUT"

echo "■ 申請TSV (-q -f)"
run_script -q -f "$TSV"
assert_contains "行1は最も悪いホスト名の結果" "行1  CN=ok.alpha.ac.jp  (ホスト名3件)  CSR: ⚠️   ACME: ❌" "$RUN_OUTPUT"
assert_contains "行2" "行2  CN=Www.Alpha.Ac.Jp  (ホスト名1件)  CSR: ✅  ACME: ✅" "$RUN_OUTPUT"
assert_contains "行5" "行5  CN=ok.alpha.ac.jp  (ホスト名1件)  CSR: ✅  ACME: ✅" "$RUN_OUTPUT"
assert_not_contains "失効申請の行はまとめに出ない" "行3  CN=" "$RUN_OUTPUT"
assert_eq "同じホスト名は1回だけ確認する" "3" "$(echo "$RUN_OUTPUT" | grep -c '^確認中: ')"
assert_eq "発行できない行があれば終了コード 2" "2" "$LAST_STATUS"

TSV_OK="$WORK_DIR/ok.tsv"
make_tsv "$TSV_OK" \
    "$DN${T}3${T}${T}${T}${T}${T}CSR${T}名${T}所属${T}a@b${T}ok.alpha.ac.jp${T}nginx${T}dNSName=www.alpha.ac.jp"
run_script -q -f "$TSV_OK"
assert_eq "すべて問題なければ終了コード 0" "0" "$LAST_STATUS"

TSV_NOTE="$WORK_DIR/note.tsv"
make_tsv "$TSV_NOTE" \
    "$DN${T}3${T}${T}${T}${T}${T}CSR${T}名${T}所属${T}a@b${T}ok.alpha.ac.jp${T}nginx${T}dNSName=www.lima.ac.jp"
run_script -q -f "$TSV_NOTE"
assert_contains "注意のあるホスト名を含む行" "CSR: ✅  ACME: ✅  (注意あり)" "$RUN_OUTPUT"
assert_eq "注意ありなら終了コード 1" "1" "$LAST_STATUS"

echo "■ 申請TSV (-f、-q なし)"
run_script -f "$TSV"
assert_eq "ホスト名ごとに詳細を表示" "3" "$(echo "$RUN_OUTPUT" | grep -c '【MPIC判定結果】')"
assert_contains "まとめも表示" "【申請行ごとのまとめ】" "$RUN_OUTPUT"

echo "■ 引数のエラー"
run_script
assert_eq "引数なし" "3" "$LAST_STATUS"
run_script -f
assert_eq "-f の引数なし" "3" "$LAST_STATUS"
run_script -f "$WORK_DIR/nofile.tsv"
assert_eq "存在しないTSV" "3" "$LAST_STATUS"
run_script -f "$TSV" ok.alpha.ac.jp
assert_eq "FQDNとTSVの両方を指定" "3" "$LAST_STATUS"
run_script -x
assert_contains "不明なオプション" "不明なオプションです: -x" "$RUN_OUTPUT"
run_script -h
assert_eq "-h は正常終了" "0" "$LAST_STATUS"
make_tsv "$WORK_DIR/empty.tsv" "a${T}b"
run_script -f "$WORK_DIR/empty.tsv"
assert_eq "確認対象のないTSV" "3" "$LAST_STATUS"

echo ""
echo "結果: 成功 $PASSED 件 / 失敗 $FAILED 件"
[ "$FAILED" -eq 0 ]
