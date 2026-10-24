#!/bin/bash
# desc: FQDN の CAA/CNAME 設定と MPIC 検証要件をチェックする
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT
#

usage() {
    echo "使用法: $0 [-q] <FQDN>"
    echo "        $0 [-q] -f <申請TSVファイル>"
    echo ""
    echo "  -f, --tsv FILE  UPKIの申請TSV(サーバ証明書 発行/更新、ACME利用情報 作成/更新)を読み込み、"
    echo "                  利用管理者FQDN(11列目)とdNSName(13列目)のホスト名をすべて確認します"
    echo "  -q, --quiet     個別の確認ログを省略し、判定のまとめだけを表示します"
    echo "  -h, --help      この使い方を表示します"
}

TARGET_FQDN=""
TSV_FILE=""
QUIET=0
while [ $# -gt 0 ]; do
    case "$1" in
        -f|--tsv)
            if [ -z "$2" ]; then
                usage
                exit 1
            fi
            TSV_FILE=$2
            shift 2
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "不明なオプションです: $1"
            usage
            exit 1
            ;;
        *)
            if [ -n "$TARGET_FQDN" ]; then
                usage
                exit 1
            fi
            TARGET_FQDN=$1
            shift
            ;;
    esac
done

# FQDNとTSVはどちらか一方だけを指定する
if [[ ( -n "$TSV_FILE" && -n "$TARGET_FQDN" ) || ( -z "$TSV_FILE" && -z "$TARGET_FQDN" ) ]]; then
    usage
    exit 1
fi
if [ -n "$TSV_FILE" ] && [ ! -r "$TSV_FILE" ]; then
    echo "TSVファイル ($TSV_FILE) を読み込めません。"
    exit 1
fi

# シンボリックリンク経由の実行でも実体のあるディレクトリを指すよう解決する
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
PSL_FILE="$SCRIPT_DIR/public_suffix_list.dat"

# Download PSL if not exists
if [ ! -f "$PSL_FILE" ]; then
    echo "Public Suffix List ($PSL_FILE) が見つかりません。ダウンロードします..."
    curl -sS https://publicsuffix.org/list/public_suffix_list.dat -o "$PSL_FILE"
    if [ $? -ne 0 ] || [ ! -s "$PSL_FILE" ]; then
        echo "Public Suffix List のダウンロードに失敗しました。"
        exit 1
    fi
fi

# eTLD+1を判定する関数
get_etld_plus_one() {
    local domain=$1
    local psl=$2
    local parts
    IFS='.' read -ra parts <<< "$domain"
    
    for (( i=0; i<${#parts[@]}; i++ )); do
        local suffix=""
        for (( j=i; j<${#parts[@]}; j++ )); do
            if [ -n "$suffix" ]; then
                suffix="$suffix.${parts[j]}"
            else
                suffix="${parts[j]}"
            fi
        done
        
        # 1. 例外ルール（!）の確認
        if grep -Fxq "!$suffix" "$psl"; then
            echo "$suffix"
            return
        fi

        # 2. 完全一致の確認
        if grep -Fxq "$suffix" "$psl"; then
            if [ $i -gt 0 ]; then
                local etld1=""
                for (( j=i-1; j<${#parts[@]}; j++ )); do
                    if [ -n "$etld1" ]; then
                        etld1="$etld1.${parts[j]}"
                    else
                        etld1="${parts[j]}"
                    fi
                done
                echo "$etld1"
                return
            else
                echo "$suffix"
                return
            fi
        fi

        # 3. ワイルドカードの確認 (*.parent)
        if [[ "$suffix" == *"."* ]]; then
            local parent=${suffix#*.}
            if grep -Fxq "*.$parent" "$psl"; then
                if [ $i -gt 0 ]; then
                    local etld1=""
                    for (( j=i-1; j<${#parts[@]}; j++ )); do
                        if [ -n "$etld1" ]; then
                            etld1="$etld1.${parts[j]}"
                        else
                            etld1="${parts[j]}"
                        fi
                    done
                    echo "$etld1"
                    return
                else
                    echo "$suffix"
                    return
                fi
            fi
        fi
    done
    
    # マッチしない場合のフォールバック（TLD+1）
    if [ ${#parts[@]} -ge 2 ]; then
        echo "${parts[${#parts[@]}-2]}.${parts[${#parts[@]}-1]}"
    else
        echo "$domain"
    fi
}

# CAAの検索アルゴリズム(RFC 8659)に沿って、CNAME追跡とeTLD+1までの親ドメイン遡りを行い、
# 実際に発行可否を左右する「実効CAAレコード」を1件だけ探索するヘルパー関数。
# あるドメインで空でないCAAレコードセットが見つかった時点でそこが実効CAAとなり、
# それより上位ドメインのCAAは無視される(見つからなければCNAME先→親ドメインの順に遡る)。
# 出力形式: "CAAが見つかったドメイン名|CAAレコードの内容" (見つからない場合は "|")
find_relevant_caa() {
    local fqdn=$1
    local dns=$2
    local psl=$3
    local dns_opt=""

    if [ -n "$dns" ]; then
        dns_opt="@$dns"
    fi

    local current="$fqdn"
    local visited=()

    while true; do
        local current_lc
        current_lc=$(echo "$current" | tr '[:upper:]' '[:lower:]')

        local v
        for v in "${visited[@]}"; do
            if [ "$v" == "$current_lc" ]; then
                echo "|"
                return
            fi
        done
        visited+=("$current_lc")

        # CNAMEがあれば参照先を正としてCAAを確認する
        # (CNAMEの張られたノードには本来他のレコードは実在せず、dig CAAも自動的にCNAME先の
        #  結果を返してしまうため、表示ドメイン名を正しくするために先にCNAMEを確認する)
        local cname
        cname=$(dig +short CNAME "$current" $dns_opt +time=3 +tries=2 | head -n 1 | sed 's/\.$//')
        if [ -n "$cname" ]; then
            current="$cname"
            continue
        fi

        local caa
        caa=$(dig +short CAA "$current" $dns_opt +time=3 +tries=2 | grep -E '^[0-9]+\s+' | sort | tr '\n' ',' | sed 's/,$//')
        if [ -n "$caa" ]; then
            echo "$current|$caa"
            return
        fi

        # CAAもCNAMEも無ければ、eTLD+1に到達するまで親ドメインへ遡る
        local etld1
        etld1=$(get_etld_plus_one "$current" "$psl")
        if [ "$current" == "$etld1" ] || [[ "$current" != *"."* ]]; then
            echo "|"
            return
        fi
        current=$(echo "$current" | cut -d'.' -f2-)
    done
}

# FQDNの確認処理本体
process_fqdn() {
    local fqdn=$1
    local dns=$2
    local dns_opt=""
    
    if [ -n "$dns" ]; then
        dns_opt="@$dns"
        echo "=== [$fqdn] をDNSサーバ $dns で確認 ==="
    else
        echo "=== [$fqdn] の確認 ==="
    fi

    # 名前解決できるか確認 (タイムアウトを防ぐために +time=3 +tries=2 を付与)
    local code=$(dig "$fqdn" $dns_opt +time=3 +tries=2 +noall +comments | grep -ioE "status: [A-Z]+" | awk '{print $2}' | tr '[:lower:]' '[:upper:]')
    # NXDOMAIN と SERVFAIL は発行方式への影響が異なるため分けて説明する
    if [[ "$code" == "NXDOMAIN" ]]; then
        echo "名前解決ができません (status: NXDOMAIN)。"
        echo "  [ACME発行の場合] 発行できません。dns-01のチャレンジは _acme-challenge.$fqdn に置く必要がありますが、RFC 8020により"
        echo "                   NXDOMAINのFQDN配下の名前も存在しないため参照できません(http-01/tls-alpn-01はA/AAAAが必要)。"
        echo "  [CSR申請の場合]  直ちに発行不可とは限りません。DCVは対象FQDNではなくADN(上位ドメイン)に対して行われるため、"
        echo "                   上位ADNでDCV済みかつCAAが適切であれば発行され得ます(以降の上位ドメインの確認結果を参照)。"
        return 1
    fi
    if [[ "$code" == "SERVFAIL" ]]; then
        echo "名前解決ができません (status: SERVFAIL)。"
        echo "  [CSR申請/ACME発行に共通] SERVFAILはCAAレコードの確認結果も不明にするため、CAはどちらの方式でも発行できません。"
        echo "                           DNSの設定(委任・DNSSEC等)の修正が必要です。"
        return 1
    fi
    if [ -z "$code" ]; then
        echo "DNSクエリがタイムアウトしたか、応答を取得できませんでした。ネットワークまたはDNSサーバーの状態を確認してください。"
        return 1
    fi

    local current_fqdn=$fqdn
    local is_cname_target=0
    local visited_fqdns=("$current_fqdn")

    while true; do
        # CAAの確認
        local caa_result=$(dig +short CAA "$current_fqdn" $dns_opt +time=3 +tries=2 | grep -E '^[0-9]+\s+')
        if [ -n "$caa_result" ]; then
            if [ $is_cname_target -eq 1 ]; then
                echo "CNAME先のCAAレコード ($current_fqdn):"
                echo "$caa_result"
            else
                echo "CAAレコード ($current_fqdn):"
                echo "$caa_result"
            fi
            
            if ! echo "$caa_result" | grep -iq "secomtrust\.net"; then
                echo "CAAレコードが存在しますが、 secomtrust.net が含まれません。(このドメイン単独でのCAA内容です。実際に発行へ影響するかはMPIC判定結果の実効CAAの確認をご参照ください)"
            fi
        else
            if [ $is_cname_target -eq 1 ]; then
                echo "CNAMEレコードの先のCAAレコードがありません ($current_fqdn)"
            else
                echo "CAAレコードがありません ($current_fqdn)"
            fi
        fi

        # CNAMEの確認
        local cname_result=$(dig +short CNAME "$current_fqdn" $dns_opt +time=3 +tries=2)
        if [ -n "$cname_result" ]; then
            local next_fqdn=$(echo "$cname_result" | head -n 1 | sed 's/\.$//')
            echo "CNAMEレコード ($current_fqdn):"
            echo "$cname_result"
            
            # CNAMEループ検知 (大文字小文字を区別せずに比較)
            local next_fqdn_lc=$(echo "$next_fqdn" | tr '[:upper:]' '[:lower:]')
            for visited in "${visited_fqdns[@]}"; do
                if [ "$(echo "$visited" | tr '[:upper:]' '[:lower:]')" == "$next_fqdn_lc" ]; then
                    echo "CNAMEのループまたは重複を検知しました ($next_fqdn)。追跡を終了します。"
                    break 2
                fi
            done
            
            current_fqdn=$next_fqdn
            visited_fqdns+=("$current_fqdn")
            is_cname_target=1
            echo "--> CNAMEの先 ($current_fqdn) を確認します"
            echo ""
        else
            echo "CNAMEレコードがありません ($current_fqdn)"
            break
        fi
    done
}

# DNS情報を取得して変数に格納するヘルパー関数
get_dns_info() {
    local fqdn=$1
    local dns=$2
    local dns_opt=""
    
    if [ -n "$dns" ]; then
        dns_opt="@$dns"
    fi

    # タイムアウトを防ぐために +time=3 +tries=2 を付与
    local status=$(dig "$fqdn" $dns_opt +time=3 +tries=2 +noall +comments | grep -ioE "status: [A-Z]+" | awk '{print $2}' | tr '[:lower:]' '[:upper:]')
    local caa=$(dig +short CAA "$fqdn" $dns_opt +time=3 +tries=2 | grep -E '^[0-9]+\s+' | sort | tr '\n' ',' | sed 's/,$//')
    local cname=$(dig +short CNAME "$fqdn" $dns_opt +time=3 +tries=2 | sort | tr '\n' ',' | sed 's/,$//')

    if [ -z "$status" ]; then
        status="TIMEOUT_OR_ERROR"
    fi

    echo "$status|$caa|$cname"
}

# MPIC判定を行う関数
# 併せて、検出した不備が「CSRによる申請」「ACMEによる発行」のそれぞれでどう現れるかを分類して出力する。
evaluate_mpic() {
    local fqdn=$1
    echo ""
    echo "=================================================="
    echo "【MPIC判定結果】 (Multi-Perspective Issuance Corroboration)"
    echo "=================================================="

    # それぞれのDNSで情報を取得
    local res_def=$(get_dns_info "$fqdn" "")
    local stat_def=$(echo "$res_def" | cut -d'|' -f1)
    local caa_def=$(echo "$res_def" | cut -d'|' -f2)
    local cname_def=$(echo "$res_def" | cut -d'|' -f3)

    local res_8888=$(get_dns_info "$fqdn" "8.8.8.8")
    local stat_8888=$(echo "$res_8888" | cut -d'|' -f1)
    local caa_8888=$(echo "$res_8888" | cut -d'|' -f2)
    local cname_8888=$(echo "$res_8888" | cut -d'|' -f3)

    local res_1111=$(get_dns_info "$fqdn" "1.1.1.1")
    local stat_1111=$(echo "$res_1111" | cut -d'|' -f1)
    local caa_1111=$(echo "$res_1111" | cut -d'|' -f2)
    local cname_1111=$(echo "$res_1111" | cut -d'|' -f3)

    # CNAME追跡・eTLD+1までの親ドメイン遡りを考慮した「実効CAAレコード」を各DNS拠点ごとに取得
    local rel_def=$(find_relevant_caa "$fqdn" "" "$PSL_FILE")
    local rel_def_domain=$(echo "$rel_def" | cut -d'|' -f1)
    local rel_def_caa=$(echo "$rel_def" | cut -d'|' -f2)

    local rel_8888=$(find_relevant_caa "$fqdn" "8.8.8.8" "$PSL_FILE")
    local rel_8888_domain=$(echo "$rel_8888" | cut -d'|' -f1)
    local rel_8888_caa=$(echo "$rel_8888" | cut -d'|' -f2)

    local rel_1111=$(find_relevant_caa "$fqdn" "1.1.1.1" "$PSL_FILE")
    local rel_1111_domain=$(echo "$rel_1111" | cut -d'|' -f1)
    local rel_1111_caa=$(echo "$rel_1111" | cut -d'|' -f2)

    local mpic_pass=1
    # 発行方式ごとの見通し (1=問題なし / 2=条件付き / 0=発行できない)
    local csr_state=1
    local acme_state=1
    local fail_reasons=()

    # 1. パブリックDNSでの名前解決失敗(SERVFAIL/無応答)
    #    SERVFAILはCAAの確認結果も「不明」にするため、MPICの裏付けが取れず両方式とも発行できない
    if [[ "$stat_8888" == "SERVFAIL" || "$stat_8888" == "TIMEOUT_OR_ERROR" || "$stat_1111" == "SERVFAIL" || "$stat_1111" == "TIMEOUT_OR_ERROR" ]]; then
        mpic_pass=0
        csr_state=0
        acme_state=0
        fail_reasons+=("・パブリックDNS (8.8.8.8 または 1.1.1.1) で名前解決に失敗しました (Status: 8.8.8.8=$stat_8888, 1.1.1.1=$stat_1111)。")
        fail_reasons+=("  [原因推測] 権威DNSサーバー側で、海外からのIPアクセス制限（GeoIPブロッキング）が行われている可能性が高いです。")
        fail_reasons+=("  [CSR申請の場合]  MPICはACME固有の仕組みではなくBR 3.2.2.4の全DCV方式(CAAの参照を含む)に適用されるため、CSR方式でも同様に発行が抑制されます。")
        fail_reasons+=("                   (現在は4つのリモート観測点のうち3点以上が主観測点と一致し、かつ2つ以上のRIR地域からの観測が必要)")
        fail_reasons+=("  [ACME発行の場合] 主観測点からのチャレンジ検証に成功しても、リモート観測点による再検証で裏付けが取れずauthorizationがinvalidになります。")
    fi

    # 2. NXDOMAIN (対象FQDN自体が引けない)
    #    ここがCSRとACMEで最も挙動が分かれる箇所。
    #    BRのDCVは対象FQDNではなくADN(Authorization Domain Name: 左のラベルを削って導出する上位ドメイン)に
    #    対して行われるため、CSR方式では上位ADNのDCV結果が再利用され発行され得る。
    #    一方ACMEはdns-01が _acme-challenge.<FQDN>、http-01/tls-alpn-01がA/AAAAを必要とし、
    #    実質ADNが対象FQDNに固定されるため発行できない。
    if [[ "$stat_def" == "NXDOMAIN" || "$stat_8888" == "NXDOMAIN" || "$stat_1111" == "NXDOMAIN" ]]; then
        mpic_pass=0
        if [[ "$stat_def" == "NXDOMAIN" && "$stat_8888" == "NXDOMAIN" && "$stat_1111" == "NXDOMAIN" ]]; then
            acme_state=0
            [ $csr_state -eq 1 ] && csr_state=2
            fail_reasons+=("・すべてのDNSサーバーでNXDOMAIN（名前解決失敗）となりました。")
            fail_reasons+=("  [ACME発行の場合] 発行できません。dns-01のチャレンジは _acme-challenge.$fqdn に置く必要がありますが、")
            fail_reasons+=("                   RFC 8020によりNXDOMAINのFQDN配下の名前も存在しないため参照できません。http-01/tls-alpn-01もA/AAAAが必要です。")
            fail_reasons+=("  [CSR申請の場合]  直ちに発行不可とは限りません。DCVは対象FQDNではなくADN(上位ドメイン)に対して行われるため、")
            fail_reasons+=("                   上位ADNでDCV済みかつCAAが適切であれば、対象FQDNがNXDOMAINでも発行され得ます。")
            fail_reasons+=("                   ただしDCVの再利用可能期間は2026-03-15以降200日に短縮されており(2027-03-15に100日、2029-03-15に10日)、")
            fail_reasons+=("                   再検証のタイミングでは上位ADN側が解決できる必要があります。")
        elif [[ "$stat_def" == "NOERROR" ]]; then
            acme_state=0
            [ $csr_state -eq 1 ] && csr_state=2
            fail_reasons+=("・デフォルトDNSでは解決できますが、パブリックDNSでNXDOMAIN（存在しない）となりました。")
            fail_reasons+=("  [原因推測] 内部ネットワーク専用のDNS（スプリットホライズン）で解決されており、外部インターネットから該当ドメインが見えていません。")
            fail_reasons+=("  [ACME発行の場合] 発行できません。CAは外部からしか参照しないため、チャレンジ用レコードを外部の権威DNSに公開する必要があります。")
            fail_reasons+=("  [CSR申請の場合]  対象FQDNが外部から見えなくても、上位ADNでDCV済みかつCAAが適切であれば発行され得ます(上記と同じ理由)。")
        else
            csr_state=0
            acme_state=0
            fail_reasons+=("・一部のDNSサーバーでNXDOMAIN（名前解決失敗）となりました (Status: Default=$stat_def, 8.8.8.8=$stat_8888, 1.1.1.1=$stat_1111)。")
            fail_reasons+=("  [CSR申請/ACME発行に共通] 観測点によって応答が異なるためMPICの裏付け(quorum)が取れず、どちらの方式でも発行が抑制されます。")
        fi
    fi

    # 3. レコードの不一致 (MPICの裏付けが取れないため方式によらず発行できない)
    if [[ "$stat_def" == "NOERROR" && "$stat_8888" == "NOERROR" && "$stat_1111" == "NOERROR" ]]; then
        if [[ "$caa_def" != "$caa_8888" || "$caa_8888" != "$caa_1111" ]]; then
            mpic_pass=0
            csr_state=0
            acme_state=0
            fail_reasons+=("・取得されたCAAレコードがDNSサーバー間で一致しませんでした。")
            fail_reasons+=("  (Default: '$caa_def', 8.8.8.8: '$caa_8888', 1.1.1.1: '$caa_1111')")
            fail_reasons+=("  [原因推測] ネットワーク環境によって異なるレコードを返しているか、DNS権威サーバー間で同期遅延が発生しています。")
            fail_reasons+=("  [CSR申請/ACME発行に共通] CAAの参照もMPICの対象です(BGPハイジャックによるCAA迂回を防ぐため)。")
            fail_reasons+=("                           観測点ごとに応答が食い違うと裏付けが取れず、どちらの方式でも発行できません。")
        fi

        if [[ "$cname_def" != "$cname_8888" || "$cname_8888" != "$cname_1111" ]]; then
            mpic_pass=0
            csr_state=0
            acme_state=0
            fail_reasons+=("・取得されたCNAMEレコードがDNSサーバー間で一致しませんでした。")
            fail_reasons+=("  (Default: '$cname_def', 8.8.8.8: '$cname_8888', 1.1.1.1: '$cname_1111')")
            fail_reasons+=("  [CSR申請の場合]  CNAME先が変わるとCAAの探索経路とADNの導出も変わるため、検証が安定せず発行できません。")
            fail_reasons+=("                   なお2026-11-15に適用期限を迎えるSC-101v2でCNAME追跡とラベル削除の順序が厳格化されます。")
            fail_reasons+=("  [ACME発行の場合] 観測点ごとに参照されるレコードが変わり、authorizationがinvalidになります。")
        fi
    fi

    # 4. 実効CAAレコード(CNAME追跡・eTLD+1までの親ドメイン遡りの末に最初に見つかったCAA)による許可確認
    #    ※ CAA(RFC 8659)はDCVとは別レイヤの「どのCAが発行してよいか」の許可リストであり、
    #      上位ドメインへ遡って探すのは仕様どおりの正常動作(NXDOMAINは障害にならない)。方式によらず発行を左右する。
    #    ※ 対象ドメイン自身に空でないCAAが見つかればそこで探索を打ち切るため、
    #      無関係な上位ドメインのCAAレコードが誤って判定に影響することはない
    #    ※ 3拠点で同じ実効CAAが得られた場合は、同じ指摘を3回繰り返さず1件にまとめる
    local caa_ng=0
    if [ "$rel_def" == "$rel_8888" ] && [ "$rel_8888" == "$rel_1111" ]; then
        if [ -n "$rel_def_domain" ] && ! echo "$rel_def_caa" | grep -iq "secomtrust\.net"; then
            caa_ng=1
            fail_reasons+=("・実効的に適用されるCAAレコード ($rel_def_domain: $rel_def_caa) に secomtrust.net が含まれません。(全DNS拠点で共通)")
        fi
    else
        if [ -n "$rel_def_domain" ] && ! echo "$rel_def_caa" | grep -iq "secomtrust\.net"; then
            caa_ng=1
            fail_reasons+=("・デフォルトDNSで実効的に適用されるCAAレコード ($rel_def_domain: $rel_def_caa) に secomtrust.net が含まれません。")
        fi
        if [ -n "$rel_8888_domain" ] && ! echo "$rel_8888_caa" | grep -iq "secomtrust\.net"; then
            caa_ng=1
            fail_reasons+=("・8.8.8.8で実効的に適用されるCAAレコード ($rel_8888_domain: $rel_8888_caa) に secomtrust.net が含まれません。")
        fi
        if [ -n "$rel_1111_domain" ] && ! echo "$rel_1111_caa" | grep -iq "secomtrust\.net"; then
            caa_ng=1
            fail_reasons+=("・1.1.1.1で実効的に適用されるCAAレコード ($rel_1111_domain: $rel_1111_caa) に secomtrust.net が含まれません。")
        fi
    fi
    if [ $caa_ng -eq 1 ]; then
        mpic_pass=0
        csr_state=0
        acme_state=0
        fail_reasons+=("  [原因推測] CAAはDCVとは別レイヤの許可リストで、発行直前(8時間以内、ACMEではfinalize時)にCAが確認します。")
        fail_reasons+=("  [CSR申請の場合]  上位ADNでのDCVが済んでいても、CAAで拒否されるため発行できません。")
        fail_reasons+=("  [ACME発行の場合] チャレンジ検証に成功しても、finalize時のCAA確認で拒否され発行できません。")
    fi

    # 呼び出し元(まとめ表示)で使うため、判定結果をグローバル変数にも残す
    MPIC_CSR_STATE=$csr_state
    MPIC_ACME_STATE=$acme_state
    MPIC_REASON=""
    if [ ${#fail_reasons[@]} -gt 0 ]; then
        MPIC_REASON=${fail_reasons[0]#・}
    fi

    if [ $mpic_pass -eq 1 ]; then
        echo "判定結果: ✅ パスする可能性が高いです。"
        echo "複数のDNS拠点からの応答（ステータス、CAA、CNAME）が一致しています。"
    else
        echo "判定結果: ❌ パスしない（エラーになる）可能性が高いです。"
        echo "以下の原因が考えられます："
        for reason in "${fail_reasons[@]}"; do
            echo "$reason"
        done
    fi

    # 発行方式ごとの見通し
    echo ""
    echo "--------------------------------------------------"
    echo "【発行方式別の見通し】"
    case $csr_state in
        1) echo "  CSR申請  : ✅ DNS/CAA面で発行を妨げる問題は見つかりませんでした。" ;;
        2) echo "  CSR申請  : ⚠️  上位ADNでDCV済み(200日以内)かつCAAが適切であれば発行され得ます。UPKI/CAへの確認を推奨します。" ;;
        0) echo "  CSR申請  : ❌ 発行できない可能性が高いです。" ;;
    esac
    case $acme_state in
        1) echo "  ACME発行 : ✅ DNS/CAA面で発行を妨げる問題は見つかりませんでした。(dns-01では別途 _acme-challenge.$fqdn のTXT設置が必要です)" ;;
        0) echo "  ACME発行 : ❌ 発行できません。" ;;
    esac
    echo "--------------------------------------------------"

    if [ $mpic_pass -eq 0 ]; then
        echo ""
        echo "※【発行方式(CSR / ACME)による違い】"
        echo "  ・MPICはACME固有の仕組みではなく、BR 3.2.2.4のすべてのDCV方式(CAAの参照を含む)に適用されます。"
        echo "    そのためCAAの不備・観測点間の不一致・SERVFAILは、CSR/ACMEどちらの方式でも発行を抑制します。"
        echo "  ・両者で挙動が分かれるのは「対象FQDN自体が引けない(NXDOMAIN)」ケースです。"
        echo "    - CSR申請 : DCVは対象FQDNではなくADN(上位ドメイン)に対して行われ再利用されるため、"
        echo "                上位ADNでDCV済み＋CAAが適切であれば、NXDOMAINのFQDNでも発行され得ます。"
        echo "    - ACME発行: dns-01は _acme-challenge.<FQDN>、http-01/tls-alpn-01はA/AAAAを必要とし、"
        echo "                ADNが対象FQDNに固定されるため発行できません。"
        echo "  ・エラーの現れ方も異なります。CSR申請では不備が「エラー338」としてUPKI側に記録されますが、"
        echo "    ACME発行ではエラー338は発生せず、order(証明書要求)ごとにACMEクライアント側のエラーとして返ります。"
        echo "    自動更新では失敗が表面化しにくいため、気付かないまま証明書が期限切れになる恐れがあります。"
        echo "  ・DCVの再利用可能期間は2026-03-15以降200日(2027-03-15に100日、2029-03-15に10日)に短縮されており、"
        echo "    CSR方式で上位ADNのDCV結果を長期間使い回す運用は成立しなくなります。"
    fi
}

# 1件のFQDNについて、上位ドメインへの遡り・パブリックDNSでの確認・MPIC判定を行う
check_one_fqdn() {
    local target=$1
    local etld_plus_one
    etld_plus_one=$(get_etld_plus_one "$target" "$PSL_FILE")
    echo "--> Public Suffix Listを元に算出された頂点ドメイン(eTLD+1): $etld_plus_one"
    echo ""
    echo "=================================================="
    echo "対象FQDNと上位ドメイン(デフォルトDNS)の確認"
    echo "=================================================="
    echo "※ ここで遡る上位ドメインは、CSR方式でDCVの対象となりうるADN(Authorization Domain Name)の候補でもあります。"
    echo ""

    local current_domain=$target
    local next_domain

    while true; do
        process_fqdn "$current_domain" ""

        if [ "$current_domain" == "$etld_plus_one" ]; then
            echo ""
            echo "--> 頂点ドメイン(eTLD+1: $current_domain) に到達しました。上位への遡りを終了します。"
            break
        fi

        # ドットが含まれていない場合は最上位(TLD)まで来たので終了(安全装置)
        if [[ "$current_domain" != *"."* ]]; then
            break
        fi

        # 最初のドットまでを削って上位ドメインへ
        next_domain=$(echo "$current_domain" | cut -d'.' -f2-)
        if [ -z "$next_domain" ]; then
            break
        fi
        current_domain=$next_domain
        echo ""
        echo "--- 上位FQDN ($current_domain) へ遡ります ---"
    done

    echo ""
    echo "=================================================="
    echo "指定DNSでの確認 (8.8.8.8)"
    echo "=================================================="
    process_fqdn "$target" "8.8.8.8"

    echo ""
    echo "=================================================="
    echo "指定DNSでの確認 (1.1.1.1)"
    echo "=================================================="
    process_fqdn "$target" "1.1.1.1"

    # MPIC判定の実行
    evaluate_mpic "$target"
}

# UPKIの申請TSVで使える形式のホスト名か (半角英数と「.」「-」のみ。ワイルドカードは不可)
HOSTNAME_RE='^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$'
is_valid_hostname() {
    [[ "$1" =~ $HOSTNAME_RE ]]
}

to_lower() {
    echo "$1" | tr '[:upper:]' '[:lower:]'
}

# 申請TSVを読み込み、申請行ごとの確認対象ホスト名を ROW_LINES / ROW_CNS / ROW_HOSTS に格納する
# - サーバ証明書 発行/更新、ACME利用情報 作成/更新のTSVは、いずれも11列目が利用管理者FQDN、
#   13列目がdNSName("dNSName=XXX,dNSName=ZZZ" 形式)。
#   11列目のFQDNは13列目に書かれていなくてもUPKI側で自動付与されるため、両方を確認対象にする
# - TSVはShift-JIS/CR+LFだが、使う列はASCIIのみで、Shift-JISの2バイト目にタブ(0x09)は現れないため
#   文字コードを変換せずにバイト単位(LC_ALL=C)で分割できる
# - 連続するタブで空の列が詰められないよう、read の区切りにはタブではなく「|」を使う
ROW_LINES=()
ROW_CNS=()
ROW_HOSTS=()
parse_tsv() {
    local file=$1
    local lineno col11 col13

    while IFS='|' read -r lineno col11 col13; do
        col11=${col11//[[:space:]]/}
        col13=${col13//[[:space:]]/}

        if [ -z "$col11" ] && [ -z "$col13" ]; then
            echo "行$lineno: 利用管理者FQDN(11列目)・dNSName(13列目)が空のため対象外とします。(失効申請などの行)"
            continue
        fi

        local hosts=()
        if [ -n "$col11" ]; then
            if is_valid_hostname "$col11"; then
                hosts+=("$col11")
            else
                echo "行$lineno: 利用管理者FQDN(11列目)「${col11}」はホスト名の形式ではないため確認対象から除外します。"
            fi
        fi

        if [ -n "$col13" ]; then
            local items item host h dup
            local count=0
            if [[ "$col13" == *"," ]]; then
                echo "行$lineno: dNSName(13列目)の末尾に「,」があります。UPKIでは申請エラーになります。"
            fi
            IFS=',' read -ra items <<< "$col13"
            for item in "${items[@]}"; do
                [ -z "$item" ] && continue
                if [[ "$item" != dNSName=* ]]; then
                    echo "行$lineno: dNSName(13列目)の要素「${item}」が「dNSName=ホスト名」の形式ではないため除外します。"
                    continue
                fi
                host=${item#dNSName=}
                if ! is_valid_hostname "$host"; then
                    echo "行$lineno: dNSName(13列目)のホスト名「${host}」は使用できない形式のため除外します。(半角英数と「.」「-」のみ。ワイルドカード不可)"
                    continue
                fi
                count=$((count + 1))
                # 11列目と同じホスト名や行内の重複は1回だけ確認する
                dup=0
                for h in "${hosts[@]}"; do
                    if [ "$(to_lower "$h")" == "$(to_lower "$host")" ]; then
                        dup=1
                        break
                    fi
                done
                [ $dup -eq 0 ] && hosts+=("$host")
            done
            if [ $count -gt 8 ]; then
                echo "行$lineno: dNSNameは8個までです(現在${count}個)。UPKIでは申請エラーになります。"
            fi
        fi

        if [ ${#hosts[@]} -eq 0 ]; then
            echo "行$lineno: 確認できるホスト名がないため対象外とします。"
            continue
        fi

        ROW_LINES+=("$lineno")
        ROW_CNS+=("$col11")
        ROW_HOSTS+=("${hosts[*]}")
    done < <(LC_ALL=C awk -F'\t' '{ sub(/\r$/, ""); if ($0 == "") next; print NR "|" $11 "|" $13 }' "$file")
}

# 確認済みFQDNの結果 (同じホスト名が複数行に出てきても1回だけ確認する。bash 3.2 互換のため連想配列は使わない)
CHECKED_FQDNS=()
CHECKED_CSR=()
CHECKED_ACME=()
CHECKED_REASON=()

# 確認済みならその添字を、未確認なら空を出力する
find_checked() {
    local fqdn_lc i
    fqdn_lc=$(to_lower "$1")
    for (( i=0; i<${#CHECKED_FQDNS[@]}; i++ )); do
        if [ "${CHECKED_FQDNS[i]}" == "$fqdn_lc" ]; then
            echo "$i"
            return
        fi
    done
}

# FQDNを1件確認して結果を記録する (確認済みなら何もしない)
# -q 指定時は遡りやパブリックDNSでの個別表示を省き、判定だけを行う
run_check() {
    local fqdn=$1
    local label=$2

    [ -n "$(find_checked "$fqdn")" ] && return

    if [ $QUIET -eq 1 ]; then
        [ -n "$label" ] && echo "確認中: $fqdn" >&2
        evaluate_mpic "$fqdn" > /dev/null
    else
        if [ -n "$label" ]; then
            echo ""
            echo "##################################################"
            echo "# [$fqdn] ($label)"
            echo "##################################################"
        fi
        check_one_fqdn "$fqdn"
    fi

    CHECKED_FQDNS+=("$(to_lower "$fqdn")")
    CHECKED_CSR+=("$MPIC_CSR_STATE")
    CHECKED_ACME+=("$MPIC_ACME_STATE")
    CHECKED_REASON+=("$MPIC_REASON")
}

# 判定値(1=問題なし / 2=条件付き / 0=発行できない)を記号にする
state_mark() {
    case $1 in
        1) echo "✅" ;;
        2) echo "⚠️ " ;;
        *) echo "❌" ;;
    esac
}

# 2つの判定のうち悪いほうを返す (0=発行できない < 2=条件付き < 1=問題なし)
worse_state() {
    if [ "$1" == "0" ] || [ "$2" == "0" ]; then
        echo 0
    elif [ "$1" == "2" ] || [ "$2" == "2" ]; then
        echo 2
    else
        echo 1
    fi
}

# 確認済みFQDN1件分の結果を1行で表示する
print_host_result() {
    local fqdn=$1
    local indent=$2
    local idx
    idx=$(find_checked "$fqdn")
    local line
    line=$(printf "%s%-40s CSR: %s  ACME: %s" "$indent" "$fqdn" "$(state_mark "${CHECKED_CSR[idx]}")" "$(state_mark "${CHECKED_ACME[idx]}")")
    if [ -n "${CHECKED_REASON[idx]}" ]; then
        line="$line  ← ${CHECKED_REASON[idx]}"
    fi
    echo "$line"
}

# 申請行ごとのまとめを表示する
# 1枚の証明書(ACMEでは1回のorder)に含まれるホスト名が1つでも発行できなければ申請全体が失敗するため、
# 行の判定は最も悪いホスト名の結果に合わせる
print_tsv_summary() {
    echo ""
    echo "=================================================="
    echo "【申請行ごとのまとめ】 ($TSV_FILE)"
    echo "=================================================="

    local r host idx
    for (( r=0; r<${#ROW_LINES[@]}; r++ )); do
        local row_csr=1
        local row_acme=1
        local n=0
        for host in ${ROW_HOSTS[r]}; do
            idx=$(find_checked "$host")
            row_csr=$(worse_state "$row_csr" "${CHECKED_CSR[idx]}")
            row_acme=$(worse_state "$row_acme" "${CHECKED_ACME[idx]}")
            n=$((n + 1))
        done

        local cn=${ROW_CNS[r]}
        [ -z "$cn" ] && cn="(利用管理者FQDN未記入)"
        echo ""
        echo "行${ROW_LINES[r]}  CN=$cn  (ホスト名${n}件)  CSR: $(state_mark "$row_csr")  ACME: $(state_mark "$row_acme")"
        for host in ${ROW_HOSTS[r]}; do
            print_host_result "$host" "    - "
        done
    done

    echo ""
    echo "--------------------------------------------------"
    echo "※ 1枚の証明書(ACMEでは1回のorder)に含まれるホスト名が1つでも発行できない場合は申請全体が失敗するため、"
    echo "  行の判定は最も悪いホスト名の結果に合わせています。"
    echo "※ ⚠️  は、上位ADNでDCV済み(200日以内)かつCAAが適切であれば発行され得る状態です。"
    if [ $QUIET -eq 1 ]; then
        echo "※ 原因の詳細は -q を付けずに実行した個別の確認ログを参照してください。"
    fi
    echo "--------------------------------------------------"
}

if [ -n "$TSV_FILE" ]; then
    echo "--> 申請TSV ($TSV_FILE) を読み込みます"
    parse_tsv "$TSV_FILE"
    if [ ${#ROW_LINES[@]} -eq 0 ]; then
        echo "確認対象のホスト名がTSVに見つかりませんでした。"
        exit 1
    fi

    for (( r=0; r<${#ROW_LINES[@]}; r++ )); do
        for host in ${ROW_HOSTS[r]}; do
            run_check "$host" "行${ROW_LINES[r]}"
        done
    done

    print_tsv_summary
else
    run_check "$TARGET_FQDN" ""
    if [ $QUIET -eq 1 ]; then
        print_host_result "$TARGET_FQDN" ""
    fi
fi
