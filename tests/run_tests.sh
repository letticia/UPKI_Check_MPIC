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

echo "■ find_relevant_caa"
assert_eq "親ドメインのCAA" 'alpha.ac.jp|0 issue "secomtrust.net"' "$(find_relevant_caa ok.alpha.ac.jp "")"
assert_eq "自身のCAAが優先" 'own.bravo.ac.jp|0 issue "secomtrust.net"' "$(find_relevant_caa own.bravo.ac.jp "")"
assert_eq "CNAME先の親ではなく元のドメインの親へ遡る" 'delta.ac.jp|0 issue "letsencrypt.org"' "$(find_relevant_caa www.delta.ac.jp "")"
assert_eq "CNAME先自身のCAA" 'www.foxtrot.ac.jp(CNAME先: foxtrot-host.net)|0 issue "letsencrypt.org"' "$(find_relevant_caa www.foxtrot.ac.jp "")"
assert_eq "CAAがどこにもない" '|' "$(find_relevant_caa plain.hotel.ac.jp "")"
assert_eq "DNS拠点ごとに異なるCAA" 'split.alpha.ac.jp|0 issue "letsencrypt.org"' "$(find_relevant_caa split.alpha.ac.jp 1.1.1.1)"

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
assert_contains "DNS拠点間のCAAの不一致" "CAAレコードがDNSサーバー間で一致しませんでした" "$RUN_OUTPUT"
run_script -q www.delta.ac.jp
assert_contains "元のドメインの親のCAAで判定" "(delta.ac.jp: 0 issue \"letsencrypt.org\")" "$RUN_OUTPUT"
run_script -q www.foxtrot.ac.jp
assert_contains "CNAME先のCAAであることを表示" "www.foxtrot.ac.jp(CNAME先: foxtrot-host.net)" "$RUN_OUTPUT"
# [理由] の行は -q のまとめには出ず、詳細表示にだけ出る
run_script iodef.charlie.ac.jp
assert_contains "iodefは許可にならない" "[理由] issueで許可されているCA(letsencrypt.org)に secomtrust.net が含まれません" "$RUN_OUTPUT"

echo "■ 入力の正規化"
run_script -q OK.ALPHA.AC.JP.
assert_contains "末尾のドットと大文字" "ok.alpha.ac.jp" "$RUN_OUTPUT"
assert_contains "末尾のドットと大文字の判定" "CSR: ✅" "$RUN_OUTPUT"
run_script -q https://ok.alpha.ac.jp/
assert_eq "URLはエラー(終了コード)" "1" "$LAST_STATUS"
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

echo "■ 申請TSV (-f、-q なし)"
run_script -f "$TSV"
assert_eq "ホスト名ごとに詳細を表示" "3" "$(echo "$RUN_OUTPUT" | grep -c '【MPIC判定結果】')"
assert_contains "まとめも表示" "【申請行ごとのまとめ】" "$RUN_OUTPUT"

echo "■ 引数のエラー"
run_script
assert_eq "引数なし" "1" "$LAST_STATUS"
run_script -f
assert_eq "-f の引数なし" "1" "$LAST_STATUS"
run_script -f "$WORK_DIR/nofile.tsv"
assert_eq "存在しないTSV" "1" "$LAST_STATUS"
run_script -f "$TSV" ok.alpha.ac.jp
assert_eq "FQDNとTSVの両方を指定" "1" "$LAST_STATUS"
run_script -x
assert_contains "不明なオプション" "不明なオプションです: -x" "$RUN_OUTPUT"
run_script -h
assert_eq "-h は正常終了" "0" "$LAST_STATUS"
make_tsv "$WORK_DIR/empty.tsv" "a${T}b"
run_script -f "$WORK_DIR/empty.tsv"
assert_eq "確認対象のないTSV" "1" "$LAST_STATUS"

echo ""
echo "結果: 成功 $PASSED 件 / 失敗 $FAILED 件"
[ "$FAILED" -eq 0 ]
