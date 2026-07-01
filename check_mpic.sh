#!/bin/bash
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT
#

if [ -z "$1" ]; then
    echo "使用法: $0 <FQDN>"
    exit 1
fi

TARGET_FQDN=$1
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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
    if [[ "$code" == "NXDOMAIN" || "$code" == "SERVFAIL" ]]; then
        echo "名前解決ができません。DNSの設定を修正しないと証明書発行が抑制されます。CSRによる申請ではエラー338の原因になる可能性があり、ACMEによる発行の場合はACMEクライアント側でエラーになります。"
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
        local caa_result=$(dig +short CAA "$current_fqdn" $dns_opt | grep -E '^[0-9]+\s+')
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
        local cname_result=$(dig +short CNAME "$current_fqdn" $dns_opt)
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
    local fail_reasons=()

    # 1. パブリックDNSでの名前解決失敗
    if [[ "$stat_8888" == "SERVFAIL" || "$stat_8888" == "TIMEOUT_OR_ERROR" || "$stat_1111" == "SERVFAIL" || "$stat_1111" == "TIMEOUT_OR_ERROR" ]]; then
        mpic_pass=0
        fail_reasons+=("・パブリックDNS (8.8.8.8 または 1.1.1.1) で名前解決に失敗しました (Status: 8.8.8.8=$stat_8888, 1.1.1.1=$stat_1111)。")
        fail_reasons+=("  [原因推測] 権威DNSサーバー側で、海外からのIPアクセス制限（GeoIPブロッキング）が行われている可能性が高いです。")
    fi

    # 2. NXDOMAIN (名前解決失敗)
    if [[ "$stat_def" == "NXDOMAIN" || "$stat_8888" == "NXDOMAIN" || "$stat_1111" == "NXDOMAIN" ]]; then
        mpic_pass=0
        if [[ "$stat_def" == "NXDOMAIN" && "$stat_8888" == "NXDOMAIN" && "$stat_1111" == "NXDOMAIN" ]]; then
            fail_reasons+=("・すべてのDNSサーバーでNXDOMAIN（名前解決失敗）となりました。")
            fail_reasons+=("  [原因推測] 対象FQDNのDNSレコード（Aレコード等）自体が存在しないため、ドメイン所有権の確認(DCV)ができず、証明書は発行できません。")
        elif [[ "$stat_def" == "NOERROR" ]]; then
            fail_reasons+=("・デフォルトDNSでは解決できますが、パブリックDNSでNXDOMAIN（存在しない）となりました。")
            fail_reasons+=("  [原因推測] 内部ネットワーク専用のDNS（スプリットホライズン）で解決されており、外部インターネットから該当ドメインが見えていません。")
        else
            fail_reasons+=("・一部のDNSサーバーでNXDOMAIN（名前解決失敗）となりました (Status: Default=$stat_def, 8.8.8.8=$stat_8888, 1.1.1.1=$stat_1111)。")
        fi
    fi

    # 3. レコードの不一致
    if [[ "$stat_def" == "NOERROR" && "$stat_8888" == "NOERROR" && "$stat_1111" == "NOERROR" ]]; then
        if [[ "$caa_def" != "$caa_8888" || "$caa_8888" != "$caa_1111" ]]; then
            mpic_pass=0
            fail_reasons+=("・取得されたCAAレコードがDNSサーバー間で一致しませんでした。")
            fail_reasons+=("  (Default: '$caa_def', 8.8.8.8: '$caa_8888', 1.1.1.1: '$caa_1111')")
            fail_reasons+=("  [原因推測] ネットワーク環境によって異なるレコードを返しているか、DNS権威サーバー間で同期遅延が発生しています。")
        fi

        if [[ "$cname_def" != "$cname_8888" || "$cname_8888" != "$cname_1111" ]]; then
            mpic_pass=0
            fail_reasons+=("・取得されたCNAMEレコードがDNSサーバー間で一致しませんでした。")
            fail_reasons+=("  (Default: '$cname_def', 8.8.8.8: '$cname_8888', 1.1.1.1: '$cname_1111')")
        fi
    fi

    # 4. 実効CAAレコード(CNAME追跡・eTLD+1までの親ドメイン遡りの末に最初に見つかったCAA)による許可確認
    #    ※ 対象ドメイン自身に空でないCAAが見つかればそこで探索を打ち切るため、
    #      無関係な上位ドメインのCAAレコードが誤って判定に影響することはない
    if [ -n "$rel_def_domain" ] && ! echo "$rel_def_caa" | grep -iq "secomtrust\.net"; then
        mpic_pass=0
        fail_reasons+=("・デフォルトDNSで実効的に適用されるCAAレコード ($rel_def_domain: $rel_def_caa) に secomtrust.net が含まれません。")
        fail_reasons+=("  [原因推測] このCAAレコードにより証明書の発行が抑制されるため、判定にパスしません。")
    fi
    if [ -n "$rel_8888_domain" ] && ! echo "$rel_8888_caa" | grep -iq "secomtrust\.net"; then
        mpic_pass=0
        fail_reasons+=("・8.8.8.8で実効的に適用されるCAAレコード ($rel_8888_domain: $rel_8888_caa) に secomtrust.net が含まれません。")
        fail_reasons+=("  [原因推測] このCAAレコードにより証明書の発行が抑制されるため、判定にパスしません。")
    fi
    if [ -n "$rel_1111_domain" ] && ! echo "$rel_1111_caa" | grep -iq "secomtrust\.net"; then
        mpic_pass=0
        fail_reasons+=("・1.1.1.1で実効的に適用されるCAAレコード ($rel_1111_domain: $rel_1111_caa) に secomtrust.net が含まれません。")
        fail_reasons+=("  [原因推測] このCAAレコードにより証明書の発行が抑制されるため、判定にパスしません。")
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
        echo ""
        echo "※証明書の発行元（CA）からのMPIC検証に失敗し、CSRによる申請の場合はエラー（例: UPKI エラー338）に、ACMEによる発行の場合はACMEクライアント側でのエラーになる恐れがあります。"
    fi
}

# eTLD+1を求める
ETLD_PLUS_ONE=$(get_etld_plus_one "$TARGET_FQDN" "$PSL_FILE")
echo "--> Public Suffix Listを元に算出された頂点ドメイン(eTLD+1): $ETLD_PLUS_ONE"
echo ""
echo "=================================================="
echo "対象FQDNと上位ドメイン(デフォルトDNS)の確認"
echo "=================================================="

current_domain=$TARGET_FQDN

while true; do
    process_fqdn "$current_domain" ""

    if [ "$current_domain" == "$ETLD_PLUS_ONE" ]; then
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
process_fqdn "$TARGET_FQDN" "8.8.8.8"

echo ""
echo "=================================================="
echo "指定DNSでの確認 (1.1.1.1)"
echo "=================================================="
process_fqdn "$TARGET_FQDN" "1.1.1.1"

# MPIC判定の実行
evaluate_mpic "$TARGET_FQDN"
