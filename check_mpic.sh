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
    echo "  --acme-method METHOD"
    echo "                  ACMEで使う検証方式 (dns-01 / http-01) を指定し、その方式で発行できるかを判定します"
    echo "                  (指定しなければ、どちらかの方式で発行できればACMEを可とします。tls-alpn-01 はUPKIでは使えません)"
    echo "  --update-psl    Public Suffix List を取り直します (FQDNやTSVを指定しなければ、取り直すだけで終了します)"
    echo "                  (指定しなくても、${PSL_MAX_AGE_DAYS}日より古ければ自動で取り直します)"
    echo "  -h, --help      この使い方を表示します"
    echo ""
    echo "終了コード: 0=すべて問題なし / 1=条件付き(⚠️)または注意あり / 2=発行できない(❌)判定あり / 3=引数やファイルのエラー"
}

TARGET_FQDN=""
TSV_FILE=""
QUIET=0

# UPKI(セコム)のCAを示すCAAの issuer-domain-name
CA_DOMAIN="secomtrust.net"

# 終了コード (Nagios などの監視ツールの慣習に合わせる)
EXIT_OK=0        # すべて問題なし
EXIT_WARNING=1   # 条件付き(⚠️)の判定、または【注意】がある
EXIT_CRITICAL=2  # 発行できない(❌)判定がある
EXIT_ERROR=3     # 引数やファイルのエラーで確認できなかった

# CAAの accounturi / validationmethods パラメータ(RFC 8657)の処理がCAに義務づけられる日 (BR 4.2.2.1.2、SC-098)
# この日より前は判定に反映せず【注意】だけを表示する。テストでは CHECK_MPIC_TODAY で今日の日付を差し替える
CAA_PARAMS_EFFECTIVE="2027-03-15"
TODAY="${CHECK_MPIC_TODAY:-$(date +%Y-%m-%d)}"

# シンボリックリンクをたどって、実体のファイルの絶対パスを求める
# (readlink -f は macOS 12.2 以前にないため、どの環境にもある readlink で1段ずつたどる)
resolve_path() {
    local path=$1
    local dir link
    while [ -L "$path" ]; do
        dir=$(cd "$(dirname "$path")" && pwd)
        link=$(readlink "$path")
        case "$link" in
            /*) path=$link ;;
            *) path="$dir/$link" ;;
        esac
    done
    echo "$(cd "$(dirname "$path")" && pwd)/$(basename "$path")"
}

# シンボリックリンク経由の実行でも実体のあるディレクトリを指すよう解決する
# (テストから source された場合もこのファイルの場所を基準にするため、$0 ではなく BASH_SOURCE を使う)
SCRIPT_DIR="$(dirname "$(resolve_path "${BASH_SOURCE[0]}")")"
# テストなどで別のリストを使えるよう、環境変数 CHECK_MPIC_PSL_FILE で差し替えられるようにする
# (差し替えたファイルは、--update-psl を指定しない限り自動更新しない)
PSL_FILE="${CHECK_MPIC_PSL_FILE:-$SCRIPT_DIR/public_suffix_list.dat}"
PSL_URL="https://publicsuffix.org/list/public_suffix_list.dat"
# この日数より古い Public Suffix List は自動で取り直す
PSL_MAX_AGE_DAYS=30
UPDATE_PSL=0

# UPKIのACMEで使える検証方式 (tls-alpn-01 は使えない)
UPKI_ACME_METHODS="dns-01 http-01"
# --acme-method で指定された方式 (空ならどちらでもよい)
ACME_METHOD=""

# コマンドライン引数を解析し、TARGET_FQDN / TSV_FILE / QUIET を設定する
parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--tsv)
                if [ -z "$2" ]; then
                    usage
                    exit $EXIT_ERROR
                fi
                TSV_FILE=$2
                shift 2
                ;;
            -q|--quiet)
                QUIET=1
                shift
                ;;
            --update-psl)
                UPDATE_PSL=1
                shift
                ;;
            --acme-method)
                case "$2" in
                    dns-01|http-01)
                        ACME_METHOD=$2
                        ;;
                    tls-alpn-01)
                        echo "tls-alpn-01 はUPKIのACMEでは使えません。--acme-method には dns-01 か http-01 を指定してください。"
                        exit $EXIT_ERROR
                        ;;
                    *)
                        echo "--acme-method には dns-01 か http-01 を指定してください。"
                        usage
                        exit $EXIT_ERROR
                        ;;
                esac
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                echo "不明なオプションです: $1"
                usage
                exit $EXIT_ERROR
                ;;
            *)
                if [ -n "$TARGET_FQDN" ]; then
                    usage
                    exit $EXIT_ERROR
                fi
                TARGET_FQDN=$1
                shift
                ;;
        esac
    done

    # FQDNとTSVはどちらか一方だけを指定する (--update-psl だけの場合はどちらもなくてよい)
    if [[ ( -n "$TSV_FILE" && -n "$TARGET_FQDN" ) || ( -z "$TSV_FILE" && -z "$TARGET_FQDN" && $UPDATE_PSL -eq 0 ) ]]; then
        usage
        exit $EXIT_ERROR
    fi
    if [ -n "$TSV_FILE" ] && [ ! -r "$TSV_FILE" ]; then
        echo "TSVファイル ($TSV_FILE) を読み込めません。"
        exit $EXIT_ERROR
    fi

    # 入力FQDNを正規化する (末尾のドットを除き、小文字にそろえる。PSLとの照合は小文字で行うため)
    TARGET_FQDN=$(echo "$TARGET_FQDN" | sed 's/\.*$//' | tr '[:upper:]' '[:lower:]')
}

# Public Suffix List を取得して差し替える。取得に失敗したら元のファイルには手を触れずに 1 を返す
# (取得途中のファイルや、PSL以外の内容(エラーページなど)で上書きしないよう、一時ファイルに取得して中身を確かめてから置き換える)
download_psl() {
    local file=$1
    local tmp="$file.tmp.$$"
    if curl -sS -f "$PSL_URL" -o "$tmp" 2>/dev/null && grep -q '===BEGIN ICANN DOMAINS===' "$tmp" 2>/dev/null; then
        mv "$tmp" "$file"
        return 0
    fi
    rm -f "$tmp"
    return 1
}

# ファイルの更新日時が指定した日数より古ければ真を返す
is_older_than_days() {
    local file=$1
    local days=$2
    [ -n "$(find "$file" -mtime +"$days" 2>/dev/null)" ]
}

# Public Suffix List を用意する
# - ファイルがなければ取得する (取得できなければ確認できないためエラー)
# - --update-psl の指定があるか、既定の場所のファイルが PSL_MAX_AGE_DAYS 日より古ければ取り直す
#   (取り直しに失敗しても、手元のリストで確認を続ける)
# - 取得や更新のお知らせは、-q のまとめを汚さないよう標準エラー出力に出す
ensure_psl() {
    if [ ! -f "$PSL_FILE" ]; then
        echo "Public Suffix List ($PSL_FILE) が見つかりません。ダウンロードします..." >&2
        if ! download_psl "$PSL_FILE"; then
            echo "Public Suffix List のダウンロードに失敗しました。" >&2
            exit $EXIT_ERROR
        fi
        return
    fi

    local reason=""
    if [ $UPDATE_PSL -eq 1 ]; then
        reason="--update-psl の指定"
    elif [ -z "$CHECK_MPIC_PSL_FILE" ] && is_older_than_days "$PSL_FILE" "$PSL_MAX_AGE_DAYS"; then
        reason="${PSL_MAX_AGE_DAYS}日より古いため"
    fi
    [ -z "$reason" ] && return

    echo "Public Suffix List ($PSL_FILE) を取り直します (${reason})..." >&2
    if download_psl "$PSL_FILE"; then
        echo "Public Suffix List を更新しました。" >&2
    else
        echo "Public Suffix List の取り直しに失敗しました。手元のリストで確認を続けます。" >&2
        if [ $UPDATE_PSL -eq 1 ] && [ -z "$TARGET_FQDN" ] && [ -z "$TSV_FILE" ]; then
            exit $EXIT_ERROR
        fi
    fi
}

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
            if [ "$i" -gt 0 ]; then
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
                if [ "$i" -gt 0 ]; then
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

# CAAレコードセットが CA_DOMAIN による(ワイルドカードでない)証明書の発行を許可しているかを RFC 8659 に沿って判定する。
# 引数: CAAレコードの内容をカンマで連結したもの (例: 0 issue "secomtrust.net",0 iodef "mailto:sec@example.ac.jp")
# 出力: 許可されていれば空、許可されていなければその理由
# - critical フラグ(128)付きの未知のタグがあれば、CAは発行してはならない
# - issue タグが1つもなければ発行は制限されない
#   (issuewild はワイルドカード証明書にのみ効き、iodef は違反の報告先で、いずれも発行の許可とは無関係)
# - issue タグがあれば、その値の issuer-domain-name(「;」より前)が CA_DOMAIN と一致するものが必要。
#   issue ";" はどのCAにも発行を許可しない
# - タグ名とドメイン名は大文字小文字を区別しない
# ※ UPKIではワイルドカード証明書を申請できないため issuewild は判定に使わない
# ※ issue の値に続く RFC 8657 のパラメータ(accounturi / validationmethods)は caa_parameter_effects で別に調べる
caa_denial_reason() {
    echo "$1" | awk -v ca="$CA_DOMAIN" '
    {
        line = $0
        # レコードの区切りのカンマ(直後が「フラグ タグ」で始まるもの)だけを改行に置き換えて分割する
        gsub(/,[0-9]+[ \t]+[A-Za-z0-9]+[ \t]+/, "\n&", line)
        n = split(line, recs, "\n")
        for (i = 1; i <= n; i++) {
            r = recs[i]
            sub(/^,/, "", r)
            if (r !~ /^[0-9]+[ \t]+[A-Za-z0-9]+/) continue
            flags = r
            sub(/[ \t].*/, "", flags)
            rest = r
            sub(/^[0-9]+[ \t]+/, "", rest)
            tag = rest
            sub(/[ \t].*/, "", tag)
            tag = tolower(tag)
            value = rest
            sub(/^[A-Za-z0-9]+[ \t]*/, "", value)
            gsub(/^"|"$/, "", value)

            if (tag != "issue" && tag != "issuewild" && tag != "iodef" && tag != "contactemail" && tag != "contactphone") {
                if (int(flags / 128) % 2 == 1 && critical == "") critical = tag
                continue
            }
            if (tag != "issue") continue

            has_issue = 1
            d = value
            sub(/;.*/, "", d)
            gsub(/[ \t]/, "", d)
            d = tolower(d)
            if (d == ca) permitted = 1
            if (d != "") issuers = (issuers == "" ? d : issuers ", " d)
        }
    }
    END {
        if (critical != "") {
            print "criticalフラグ付きの未知のタグ(" critical ")があるため、どのCAも発行できません"
        } else if (has_issue && !permitted) {
            if (issuers == "") {
                print "issue \";\" によりすべてのCAの発行が禁止されています"
            } else {
                print "issueで許可されているCA(" issuers ")に " ca " が含まれません"
            }
        }
    }'
}

# CA_DOMAIN を許可する issue レコードに付いた RFC 8657 のパラメータが、CSR申請 / ACME発行に与える影響を調べる。
# 引数: caa_denial_reason と同じ形式のCAAレコード (CA_DOMAIN による発行が許可されていることが前提)
# 出力: "キー=値" の行
#   has_params   CA_DOMAIN の issue レコードに accounturi / validationmethods が付いていれば 1
#   acme_ok      UPKIのACMEで使える検証方式を許可する(validationmethods がないか、その方式を含む)レコードがあれば 1
#   acme_methods ACMEで使える方式を validationmethods に書かれたとおりに並べたもの (validationmethods のないレコードがあれば "all")
#   acme_allowed ACMEで使える方式を dns-01 / http-01 の名前で並べたもの (acme_methods の ca-tbr-N を言い換えたもの)
#   acme_tbr_only ACMEの方式を ca-tbr-7 / 19 の形でしか許可していなければ 1
#                 (BRは同じ方式を表すラベルのどれでも許可することを推奨(SHOULD)するにとどまるため)
#   acme_acct    ACMEで使えるレコードがすべて accounturi 付きなら、その値 (なければ空)
#   csr_ok       パラメータのないレコードがあれば 1 (CSR申請で使う方式やアカウントによらず許可される)
#   params       パラメータの内容 (表示用)
# - パラメータのない issue "secomtrust.net" はどのアカウント・方式でも許可するため、1つでもあれば制限はない
# - ACMEの方式は、UPKIのACMEで使える dns-01 / http-01 (IANA の登録名) と、同じ方式を表す BR の ca-tbr-7 / 19。
#   tls-alpn-01 (ca-tbr-20) はUPKIのACMEで使えないため、これだけを許可するレコードはACMEを許可しないものとして扱う
# - BR では小文字が正式な表記だが、CAが大文字小文字を区別しない照合をしてもよいため、ここでは区別しない
# - UPKIのCSR申請でCAがどのBR 3.2.2.4の方式を使うか、ACME以外の accounturi をどう定めるかは不明なため、
#   パラメータで制限されている場合のCSR申請は「要確認」とする
caa_parameter_effects() {
    echo "$1" | awk -v ca="$CA_DOMAIN" '
    BEGIN {
        # UPKIのACMEで使える方式のラベル → dns-01 / http-01 の名前
        acme["dns-01"] = "dns-01"; acme["ca-tbr-7"] = "dns-01"
        acme["http-01"] = "http-01"; acme["ca-tbr-19"] = "http-01"
        all_acct = 1
    }
    {
        line = $0
        gsub(/,[0-9]+[ \t]+[A-Za-z0-9]+[ \t]+/, "\n&", line)
        n = split(line, recs, "\n")
        for (i = 1; i <= n; i++) {
            r = recs[i]
            sub(/^,/, "", r)
            if (r !~ /^[0-9]+[ \t]+[Ii][Ss][Ss][Uu][Ee][ \t]/) continue
            value = r
            sub(/^[0-9]+[ \t]+[A-Za-z0-9]+[ \t]*/, "", value)
            gsub(/^"|"$/, "", value)

            np = split(value, parts, ";")
            d = parts[1]
            gsub(/[ \t]/, "", d)
            if (tolower(d) != ca) continue

            acct = ""
            vm = ""
            for (j = 2; j <= np; j++) {
                p = parts[j]
                gsub(/[ \t]/, "", p)
                if (p == "") continue
                k = tolower(p)
                sub(/=.*/, "", k)
                v = p
                sub(/^[^=]*=?/, "", v)
                if (k == "accounturi") acct = v
                if (k == "validationmethods") vm = tolower(v)
                if (k == "accounturi" || k == "validationmethods") {
                    has_params = 1
                    params = (params == "" ? p : params "; " p)
                }
            }

            if (acct == "" && vm == "") csr_ok = 1

            rec_acme = 0
            if (vm == "") {
                rec_acme = 1
                methods_all = 1
                allowed["dns-01"] = 1
                allowed["http-01"] = 1
            } else {
                nl = split(vm, labels, ",")
                for (m = 1; m <= nl; m++) {
                    if (labels[m] in acme) {
                        rec_acme = 1
                        allowed[acme[labels[m]]] = 1
                        if (labels[m] !~ /^ca-tbr-/) iana = 1
                        if (!(labels[m] in seen)) {
                            seen[labels[m]] = 1
                            methods = (methods == "" ? labels[m] : methods "," labels[m])
                        }
                    }
                }
            }
            if (rec_acme) {
                acme_ok = 1
                if (acct == "") all_acct = 0
                else accts = (accts == "" ? acct : accts ", " acct)
            }
        }
    }
    END {
        print "has_params=" (has_params ? 1 : 0)
        print "acme_ok=" (acme_ok ? 1 : 0)
        print "acme_methods=" (methods_all ? "all" : methods)
        canon = ""
        if ("dns-01" in allowed) canon = "dns-01"
        if ("http-01" in allowed) canon = (canon == "" ? "http-01" : canon ",http-01")
        print "acme_allowed=" canon
        print "acme_tbr_only=" (acme_ok && !methods_all && !iana ? 1 : 0)
        print "acme_acct=" (acme_ok && all_acct ? accts : "")
        print "csr_ok=" (csr_ok ? 1 : 0)
        print "params=" params
    }'
}

# "キー=値" の行から、指定したキーの値を取り出す
kv_get() {
    echo "$1" | sed -n "s/^$2=//p"
}

# CAAレコードセットを取得するヘルパー関数。
# CAAの問い合わせではリゾルバがCNAMEをたどるため、実際にCAAが置かれているドメイン(CNAMEの参照先)もあわせて返す。
# 出力形式: "CAAが置かれているドメイン名(小文字)|CAAレコードの内容(ソートしてカンマ区切り)" (見つからない場合は "|")
query_caa() {
    local name=$1
    local dns_opt=$2
    local answer
    answer=$(dig CAA "$name" ${dns_opt:+"$dns_opt"} +time=3 +tries=2 +noall +answer | awk '$4 == "CAA" { owner = $1; $1 = $2 = $3 = $4 = ""; sub(/^ +/, ""); print owner "\t" $0 }')
    if [ -z "$answer" ]; then
        echo "|"
        return
    fi
    local owner caa
    owner=$(echo "$answer" | head -n 1 | cut -f1 | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')
    caa=$(echo "$answer" | cut -f2- | sort | tr '\n' ',' | sed 's/,$//')
    echo "$owner|$caa"
}

# CAAの検索アルゴリズム(RFC 8659 3節)に沿って、実際に発行可否を左右する「実効CAAレコード」を1件だけ探索するヘルパー関数。
# 対象FQDNからラベルを1つずつ削って親ドメインへ遡り、空でないCAAレコードセットが最初に見つかったものを採用する
# (見つかった時点で、それより上位ドメインのCAAは無視される)。
# - 各ドメインのCAAの問い合わせではCNAMEがたどられるため、CNAMEの参照先に置かれたCAAも対象になる
# - ただし見つからなかったときに遡るのは「元のドメインの親」であり、CNAMEの参照先の親ドメインは探さない
#   (参照先の親まで遡るのは旧仕様 RFC 6844 の動作で、RFC 8659 で廃止された)
# - 遡りはDNSルートの直前(TLD)まで行う
# 出力形式: "CAAが見つかったドメイン名|CAAレコードの内容" (見つからない場合は "|")
#   CNAMEの参照先で見つかった場合のドメイン名は "対象ドメイン(CNAME先: 参照先ドメイン)" とする
find_relevant_caa() {
    local fqdn=$1
    local dns=$2
    local dns_opt=""

    if [ -n "$dns" ]; then
        dns_opt="@$dns"
    fi

    local current=$fqdn
    local res owner caa
    while [ -n "$current" ]; do
        res=$(query_caa "$current" "$dns_opt")
        owner=${res%%|*}
        caa=${res#*|}
        if [ -n "$caa" ]; then
            if [ "$owner" != "$(to_lower "$current")" ]; then
                echo "$current(CNAME先: $owner)|$caa"
            else
                echo "$current|$caa"
            fi
            return
        fi

        # ドットが含まれていなければTLDまで確認したので終了
        if [[ "$current" != *"."* ]]; then
            break
        fi
        current=${current#*.}
    done
    echo "|"
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
    local code
    code=$(dig "$fqdn" ${dns_opt:+"$dns_opt"} +time=3 +tries=2 +noall +comments | grep -ioE "status: [A-Z]+" | awk '{print $2}' | tr '[:lower:]' '[:upper:]')
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
        if is_dnssec_failure "$fqdn" "$dns"; then
            echo "  署名の検証を省く(+cd)と解決できるため、DNSSECの検証失敗が原因です。"
        fi
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
        # CNAMEが張られている場合、CAAの問い合わせは参照先の結果を返すため、
        # このドメイン自身のCAAとしては表示せず、参照先の確認結果に任せる
        local caa_res
        caa_res=$(query_caa "$current_fqdn" "$dns_opt")
        local caa_owner=${caa_res%%|*}
        local caa_result=""
        if [ "$caa_owner" == "$(to_lower "$current_fqdn")" ]; then
            caa_result=$(dig +short CAA "$current_fqdn" ${dns_opt:+"$dns_opt"} +time=3 +tries=2 | grep -E '^[0-9]+\s+')
        fi
        if [ -n "$caa_result" ]; then
            if [ $is_cname_target -eq 1 ]; then
                echo "CNAME先のCAAレコード ($current_fqdn):"
                echo "$caa_result"
            else
                echo "CAAレコード ($current_fqdn):"
                echo "$caa_result"
            fi

            local caa_reason
            caa_reason=$(caa_denial_reason "${caa_res#*|}")
            if [ -n "$caa_reason" ]; then
                echo "このCAAレコードでは $CA_DOMAIN による発行が許可されていません ($caa_reason)。(このドメイン単独でのCAA内容です。実際に発行へ影響するかはMPIC判定結果の実効CAAの確認をご参照ください)"
            fi
        elif [ -n "$caa_owner" ]; then
            echo "CAAレコードはCNAMEの先 ($caa_owner) にあります ($current_fqdn)"
        else
            if [ $is_cname_target -eq 1 ]; then
                echo "CNAMEレコードの先のCAAレコードがありません ($current_fqdn)"
            else
                echo "CAAレコードがありません ($current_fqdn)"
            fi
        fi

        # CNAMEの確認
        local cname_result
        cname_result=$(dig +short CNAME "$current_fqdn" ${dns_opt:+"$dns_opt"} +time=3 +tries=2)
        if [ -n "$cname_result" ]; then
            local next_fqdn
            next_fqdn=$(echo "$cname_result" | head -n 1 | sed 's/\.$//')
            echo "CNAMEレコード ($current_fqdn):"
            echo "$cname_result"
            
            # CNAMEループ検知 (大文字小文字を区別せずに比較)
            local next_fqdn_lc
            next_fqdn_lc=$(echo "$next_fqdn" | tr '[:upper:]' '[:lower:]')
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
    local status
    status=$(dig "$fqdn" ${dns_opt:+"$dns_opt"} +time=3 +tries=2 +noall +comments | grep -ioE "status: [A-Z]+" | awk '{print $2}' | tr '[:lower:]' '[:upper:]')
    local caa
    caa=$(dig +short CAA "$fqdn" ${dns_opt:+"$dns_opt"} +time=3 +tries=2 | grep -E '^[0-9]+\s+' | sort | tr '\n' ',' | sed 's/,$//')
    local cname
    cname=$(dig +short CNAME "$fqdn" ${dns_opt:+"$dns_opt"} +time=3 +tries=2 | sort | tr '\n' ',' | sed 's/,$//')

    if [ -z "$status" ]; then
        status="TIMEOUT_OR_ERROR"
    fi

    echo "$status|$caa|$cname"
}

# SERVFAIL の原因が DNSSEC の検証失敗かを調べる。
# 署名の検証を省く +cd (Checking Disabled) を付けると解決できる場合は、DNSSEC の検証失敗と判断する
# (署名の期限切れ、DSレコードとDNSKEYの不一致、鍵の更新(ロールオーバー)の失敗など)
is_dnssec_failure() {
    local fqdn=$1
    local dns=$2
    local dns_opt=""
    if [ -n "$dns" ]; then
        dns_opt="@$dns"
    fi
    local status
    status=$(dig "$fqdn" ${dns_opt:+"$dns_opt"} +cd +time=3 +tries=2 +noall +comments | grep -ioE "status: [A-Z]+" | awk '{print toupper($2)}')
    [ "$status" == "NOERROR" ] || [ "$status" == "NXDOMAIN" ]
}

# 権威DNSサーバーへの直接問い合わせの結果
# (表示と判定で同じFQDNを2回問い合わせないよう、最後に確認したFQDNの結果を保持する)
AUTH_FQDN=""
AUTH_ZONE=""
AUTH_DS=""        # 親ゾーンにあるDSレコード (空なら署名なし)
AUTH_SERVERS=()   # "NS名 (IPv4アドレス)"
AUTH_STATUS=()
AUTH_SERIAL=()
AUTH_CAA=()
AUTH_CNAME=()
AUTH_NO_V4=()     # IPv4アドレスが見つからなかったNS名

# 対象FQDNが属するゾーンの権威DNSサーバーを特定し、各サーバーへ再帰なし(+norecurse)で直接問い合わせる。
# パブリックDNSはキャッシュを持ち、国内の拠点から応答するため、権威DNSサーバー間の不一致や
# 一部のサーバーの無応答(CAの観測点によって結果が変わる原因)は直接問い合わせないと見えない。
# - ゾーンは、対象FQDNから eTLD+1 まで遡って最初にNSレコードが見つかったドメインとする
# - IPv6での到達性は、確認する側の端末にIPv6がないと誤って失敗するため確認しない
collect_auth_info() {
    local fqdn=$1
    [ "$AUTH_FQDN" == "$fqdn" ] && return

    AUTH_FQDN=$fqdn
    AUTH_ZONE=""
    AUTH_DS=""
    AUTH_SERVERS=()
    AUTH_STATUS=()
    AUTH_SERIAL=()
    AUTH_CAA=()
    AUTH_CNAME=()
    AUTH_NO_V4=()

    local etld1 name ns_list=""
    etld1=$(get_etld_plus_one "$fqdn" "$PSL_FILE")
    name=$fqdn
    while [ -n "$name" ]; do
        ns_list=$(dig NS "$name" +time=3 +tries=2 +noall +answer | awk -v n="$name" '
            { owner = tolower($1); sub(/\.$/, "", owner) }
            owner == n && $4 == "NS" { v = tolower($5); sub(/\.$/, "", v); print v }' | sort -u)
        if [ -n "$ns_list" ]; then
            AUTH_ZONE=$name
            break
        fi
        if [ "$name" == "$etld1" ] || [[ "$name" != *"."* ]]; then
            break
        fi
        name=${name#*.}
    done
    [ -z "$AUTH_ZONE" ] && return

    # 親ゾーンにDSレコードがあれば、このゾーンはDNSSECで署名されている
    AUTH_DS=$(dig +short DS "$AUTH_ZONE" +time=3 +tries=2 | grep -E '^[0-9]+ ')

    local ns addrs addr opt status serial caa cname
    for ns in $ns_list; do
        addrs=$(dig +short A "$ns" +time=3 +tries=2 | grep -E '^[0-9]+(\.[0-9]+){3}$')
        if [ -z "$addrs" ]; then
            AUTH_NO_V4+=("$ns")
            continue
        fi
        for addr in $addrs; do
            opt="@$addr"
            AUTH_SERVERS+=("$ns ($addr)")
            status=$(dig "$fqdn" "$opt" +norecurse +time=3 +tries=2 +noall +comments | grep -ioE "status: [A-Z]+" | awk '{print toupper($2)}')
            [ -z "$status" ] && status="TIMEOUT_OR_ERROR"
            AUTH_STATUS+=("$status")
            # 応答しない・拒否するサーバーには、それ以上問い合わせない (タイムアウト待ちを重ねないため)
            if [ "$status" != "NOERROR" ] && [ "$status" != "NXDOMAIN" ]; then
                AUTH_SERIAL+=("")
                AUTH_CAA+=("")
                AUTH_CNAME+=("")
                continue
            fi
            serial=$(dig +short SOA "$AUTH_ZONE" "$opt" +norecurse +time=3 +tries=2 | awk 'NR == 1 { print $3 }')
            caa=$(dig CAA "$fqdn" "$opt" +norecurse +time=3 +tries=2 +noall +answer | awk -v n="$fqdn" '
                { owner = tolower($1); sub(/\.$/, "", owner) }
                owner == n && $4 == "CAA" { $1 = $2 = $3 = $4 = ""; sub(/^ +/, ""); print }' | sort | tr '\n' ',' | sed 's/,$//')
            cname=$(dig CNAME "$fqdn" "$opt" +norecurse +time=3 +tries=2 +noall +answer | awk -v n="$fqdn" '
                { owner = tolower($1); sub(/\.$/, "", owner) }
                owner == n && $4 == "CNAME" { v = tolower($5); sub(/\.$/, "", v); print v }' | sort | tr '\n' ',' | sed 's/,$//')
            AUTH_SERIAL+=("$serial")
            AUTH_CAA+=("$caa")
            AUTH_CNAME+=("$cname")
        done
    done
}

# 権威DNSサーバーごとの応答を表示する
print_auth_info() {
    local fqdn=$1
    collect_auth_info "$fqdn"

    if [ -z "$AUTH_ZONE" ]; then
        echo "権威DNSサーバー(NSレコード)を特定できませんでした。"
        return
    fi
    echo "ゾーン: $AUTH_ZONE"
    if [ -n "$AUTH_DS" ]; then
        echo "DNSSEC: 署名あり (親ゾーンにDSレコードがあります。検証の成否はMPIC判定結果をご参照ください)"
    else
        echo "DNSSEC: 署名なし (親ゾーンにDSレコードがありません)"
    fi
    local i
    for (( i=0; i<${#AUTH_SERVERS[@]}; i++ )); do
        echo "--- ${AUTH_SERVERS[i]} ---"
        echo "  status: ${AUTH_STATUS[i]}"
        if [ "${AUTH_STATUS[i]}" == "NOERROR" ] || [ "${AUTH_STATUS[i]}" == "NXDOMAIN" ]; then
            echo "  SOAシリアル: ${AUTH_SERIAL[i]:-(取得できず)}"
            echo "  CAA: ${AUTH_CAA[i]:-(なし)}"
            echo "  CNAME: ${AUTH_CNAME[i]:-(なし)}"
        fi
    done
    for (( i=0; i<${#AUTH_NO_V4[@]}; i++ )); do
        echo "--- ${AUTH_NO_V4[i]} ---"
        echo "  IPv4アドレスが見つからないため確認していません。"
    done
}

# プライベートアドレスなど、インターネット上のCAから接続できないアドレスなら真を返す
# IPv4: 0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.168/16
# IPv6: ::, ::1, fc00::/7 (ユニークローカル), fe80::/10 (リンクローカル)
is_private_ip() {
    echo "$1" | awk '
        /:/ {
            a = tolower($0)
            if (a == "::" || a == "::1" || a ~ /^f[cd]/ || a ~ /^fe[89ab]/) exit 0
            exit 1
        }
        {
            split($0, o, ".")
            o1 = o[1] + 0
            o2 = o[2] + 0
            if (o1 == 0 || o1 == 10 || o1 == 127) exit 0
            if (o1 == 100 && o2 >= 64 && o2 <= 127) exit 0
            if (o1 == 169 && o2 == 254) exit 0
            if (o1 == 172 && o2 >= 16 && o2 <= 31) exit 0
            if (o1 == 192 && o2 == 168) exit 0
            exit 1
        }'
}

# ACME向けの事前確認の結果 (表示と判定で同じFQDNを2回問い合わせないよう、最後に確認したFQDNの結果を保持する)
ACME_FQDN=""
ACME_CHAL_STATUS=""   # _acme-challenge.<FQDN> のステータス (パブリックDNSごと)
ACME_CHAL_BAD=0       # _acme-challenge.<FQDN> の名前解決に失敗(SERVFAILなど)したら 1
ACME_CHAL_CNAME=""    # _acme-challenge.<FQDN> のCNAMEの参照先 (dns-01 の委任)
ACME_CHAL_DANGLING=0  # CNAMEの参照先が存在しない(NXDOMAIN)なら 1
ACME_CHAL_TXT=""      # _acme-challenge.<FQDN> に残っているTXTレコード
ACME_PUBLIC_ADDRS=""  # CAから接続できるアドレス (A / AAAA)
ACME_PUBLIC_V6=""     # そのうちIPv6のアドレス
ACME_PRIVATE_ADDRS="" # プライベートアドレスなど、CAから接続できないアドレス

# UPKIのACMEで使える検証方式(dns-01 / http-01)が、DNSの面で使えるかを確かめるための情報を集める。
# CAはインターネット上から確認するため、パブリックDNS (8.8.8.8 / 1.1.1.1) に問い合わせる。
# - dns-01: _acme-challenge.<FQDN> が名前解決できること (TXTはACMEクライアントが検証のたびに設置するため、
#   今はなくても(NXDOMAINでも)よい)。CNAMEで委任している場合は、参照先が存在することも確かめる
# - http-01: FQDNに、CAが接続できるアドレス(A / AAAA)があること
#   (CDNなどではDNSサーバーごとに違うアドレスを返すのが普通なので、アドレスはDNSサーバー間で比べず、両方の結果を合わせる)
collect_acme_info() {
    local fqdn=$1
    [ "$ACME_FQDN" == "$fqdn" ] && return

    ACME_FQDN=$fqdn
    ACME_CHAL_STATUS=""
    ACME_CHAL_BAD=0
    ACME_CHAL_CNAME=""
    ACME_CHAL_DANGLING=0
    ACME_CHAL_TXT=""
    ACME_PUBLIC_ADDRS=""
    ACME_PUBLIC_V6=""
    ACME_PRIVATE_ADDRS=""

    local name="_acme-challenge.$fqdn"
    local dns status first_status=""
    for dns in 8.8.8.8 1.1.1.1; do
        status=$(dig TXT "$name" "@$dns" +time=3 +tries=2 +noall +comments | grep -ioE "status: [A-Z]+" | awk '{print toupper($2)}')
        [ -z "$status" ] && status="TIMEOUT_OR_ERROR"
        [ -z "$first_status" ] && first_status=$status
        ACME_CHAL_STATUS="${ACME_CHAL_STATUS:+$ACME_CHAL_STATUS, }$dns=$status"
        if [ "$status" != "NOERROR" ] && [ "$status" != "NXDOMAIN" ]; then
            ACME_CHAL_BAD=1
        fi
    done
    ACME_CHAL_CNAME=$(dig +short CNAME "$name" @8.8.8.8 +time=3 +tries=2 | head -n 1 | sed 's/\.$//')
    # CNAMEがあるのにTXTの問い合わせがNXDOMAINなら、参照先が存在しない
    if [ -n "$ACME_CHAL_CNAME" ] && [ "$first_status" == "NXDOMAIN" ]; then
        ACME_CHAL_DANGLING=1
    fi
    ACME_CHAL_TXT=$(dig +short TXT "$name" @8.8.8.8 +time=3 +tries=2 | grep '^"' | tr '\n' ',' | sed 's/,$//; s/,/, /g')

    local addrs addr
    addrs=$(for dns in 8.8.8.8 1.1.1.1; do
        dig +short A "$fqdn" "@$dns" +time=3 +tries=2 | grep -E '^[0-9]+(\.[0-9]+){3}$'
        dig +short AAAA "$fqdn" "@$dns" +time=3 +tries=2 | grep ':'
    done | sort -u)
    for addr in $addrs; do
        if is_private_ip "$addr"; then
            ACME_PRIVATE_ADDRS="${ACME_PRIVATE_ADDRS:+$ACME_PRIVATE_ADDRS, }$addr"
        else
            ACME_PUBLIC_ADDRS="${ACME_PUBLIC_ADDRS:+$ACME_PUBLIC_ADDRS, }$addr"
            [[ "$addr" == *":"* ]] && ACME_PUBLIC_V6="${ACME_PUBLIC_V6:+$ACME_PUBLIC_V6, }$addr"
        fi
    done
}

# dns-01 で発行できない理由を出力する (発行できれば何も出力しない)
acme_dns01_problem() {
    if [ "$ACME_CHAL_BAD" == "1" ]; then
        echo "_acme-challenge.$ACME_FQDN の名前解決に失敗しました ($ACME_CHAL_STATUS)"
    fi
}

# http-01 で発行できない理由を出力する (発行できれば何も出力しない)
acme_http01_problem() {
    if [ -z "$ACME_PUBLIC_ADDRS" ] && [ -z "$ACME_PRIVATE_ADDRS" ]; then
        echo "Aレコード・AAAAレコードがありません"
    elif [ -z "$ACME_PUBLIC_ADDRS" ]; then
        echo "アドレスがすべてプライベートアドレスのため、CAが接続できません ($ACME_PRIVATE_ADDRS)"
    fi
}

# ACME向けの事前確認の結果を表示する
print_acme_info() {
    local fqdn=$1
    collect_acme_info "$fqdn"

    local problem
    if [ -n "$ACME_METHOD" ]; then
        echo "--acme-method で指定された検証方式: $ACME_METHOD"
    fi
    echo "--- dns-01 (_acme-challenge.$fqdn) ---"
    echo "  status: $ACME_CHAL_STATUS"
    echo "  CNAME: ${ACME_CHAL_CNAME:-(なし)}"
    echo "  TXT: ${ACME_CHAL_TXT:-(なし)}"
    if [ -n "$ACME_CHAL_TXT" ]; then
        echo "  (残っているTXTレコードは検証の妨げにはなりません。ACMEクライアントが検証のたびに設置します)"
    fi
    problem=$(acme_dns01_problem)
    if [ -n "$problem" ]; then
        echo "  → 使えません: $problem"
    elif [ "$ACME_CHAL_DANGLING" == "1" ]; then
        echo "  → 注意: CNAMEの参照先 ($ACME_CHAL_CNAME) が存在しません"
    else
        echo "  → DNSの面では使えます"
    fi

    echo "--- http-01 (A / AAAA) ---"
    echo "  CAが接続できるアドレス: ${ACME_PUBLIC_ADDRS:-(なし)}"
    if [ -n "$ACME_PRIVATE_ADDRS" ]; then
        echo "  プライベートアドレス: $ACME_PRIVATE_ADDRS"
    fi
    problem=$(acme_http01_problem)
    if [ -n "$problem" ]; then
        echo "  → 使えません: $problem"
    else
        echo "  → DNSの面では使えます (80番ポートへの実際の接続は確認していません)"
    fi

    echo "--- tls-alpn-01 ---"
    echo "  → UPKIのACMEでは使えません"
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
    local res_def
    res_def=$(get_dns_info "$fqdn" "")
    local stat_def
    stat_def=$(echo "$res_def" | cut -d'|' -f1)
    local caa_def
    caa_def=$(echo "$res_def" | cut -d'|' -f2)
    local cname_def
    cname_def=$(echo "$res_def" | cut -d'|' -f3)

    local res_8888
    res_8888=$(get_dns_info "$fqdn" "8.8.8.8")
    local stat_8888
    stat_8888=$(echo "$res_8888" | cut -d'|' -f1)
    local caa_8888
    caa_8888=$(echo "$res_8888" | cut -d'|' -f2)
    local cname_8888
    cname_8888=$(echo "$res_8888" | cut -d'|' -f3)

    local res_1111
    res_1111=$(get_dns_info "$fqdn" "1.1.1.1")
    local stat_1111
    stat_1111=$(echo "$res_1111" | cut -d'|' -f1)
    local caa_1111
    caa_1111=$(echo "$res_1111" | cut -d'|' -f2)
    local cname_1111
    cname_1111=$(echo "$res_1111" | cut -d'|' -f3)

    # 親ドメインへの遡り(TLDまで)とCNAMEの参照先を考慮した「実効CAAレコード」を各DNS拠点ごとに取得
    local rel_def
    rel_def=$(find_relevant_caa "$fqdn" "")
    local rel_def_domain
    rel_def_domain=$(echo "$rel_def" | cut -d'|' -f1)
    local rel_def_caa
    rel_def_caa=$(echo "$rel_def" | cut -d'|' -f2)

    local rel_8888
    rel_8888=$(find_relevant_caa "$fqdn" "8.8.8.8")
    local rel_8888_domain
    rel_8888_domain=$(echo "$rel_8888" | cut -d'|' -f1)
    local rel_8888_caa
    rel_8888_caa=$(echo "$rel_8888" | cut -d'|' -f2)

    local rel_1111
    rel_1111=$(find_relevant_caa "$fqdn" "1.1.1.1")
    local rel_1111_domain
    rel_1111_domain=$(echo "$rel_1111" | cut -d'|' -f1)
    local rel_1111_caa
    rel_1111_caa=$(echo "$rel_1111" | cut -d'|' -f2)

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

        # 8.8.8.8 / 1.1.1.1 はDNSSECの検証を行うため、署名に不備があるとSERVFAILを返す。
        # GeoIPブロッキングと見分けるため、SERVFAILだったリゾルバに +cd を付けて問い合わせ直す
        local dnssec_bogus=()
        [ "$stat_8888" == "SERVFAIL" ] && is_dnssec_failure "$fqdn" "8.8.8.8" && dnssec_bogus+=("8.8.8.8")
        [ "$stat_1111" == "SERVFAIL" ] && is_dnssec_failure "$fqdn" "1.1.1.1" && dnssec_bogus+=("1.1.1.1")

        if [ ${#dnssec_bogus[@]} -gt 0 ]; then
            fail_reasons+=("・DNSSECの検証に失敗したため、パブリックDNS (${dnssec_bogus[*]}) で名前解決できませんでした (Status: 8.8.8.8=$stat_8888, 1.1.1.1=$stat_1111)。")
            fail_reasons+=("  [原因推測] 署名の検証を省く(+cd)と解決できるため、DNSSECの署名に不備があります。")
            fail_reasons+=("             署名の期限切れ、親ゾーンのDSレコードとDNSKEYの不一致、鍵の更新(ロールオーバー)の失敗などが考えられます。")
            fail_reasons+=("             DNSVizなどの診断ツールで、どの段階で検証に失敗しているかを確認してください。")
            fail_reasons+=("  [CSR申請/ACME発行に共通] 2026-03-15以降、CAはDNSSECの検証が必須です(SC-085v2)。")
            fail_reasons+=("                           検証に失敗するドメインはCAAやDCVの確認ができないため、どちらの方式でも発行できません。")
        else
            fail_reasons+=("・パブリックDNS (8.8.8.8 または 1.1.1.1) で名前解決に失敗しました (Status: 8.8.8.8=$stat_8888, 1.1.1.1=$stat_1111)。")
            fail_reasons+=("  [原因推測] 権威DNSサーバー側で、海外からのIPアクセス制限（GeoIPブロッキング）が行われている可能性が高いです。")
            fail_reasons+=("             (署名の検証を省く(+cd)と解決できるかも確認しましたが、DNSSECの検証失敗ではありませんでした)")
            fail_reasons+=("  [CSR申請の場合]  MPICはACME固有の仕組みではなくBR 3.2.2.4の全DCV方式(CAAの参照を含む)に適用されるため、CSR方式でも同様に発行が抑制されます。")
            fail_reasons+=("                   (現在は4つのリモート観測点のうち3点以上が主観測点と一致し、かつ2つ以上のRIR地域からの観測が必要)")
            fail_reasons+=("  [ACME発行の場合] 主観測点からのチャレンジ検証に成功しても、リモート観測点による再検証で裏付けが取れずauthorizationがinvalidになります。")
        fi
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

    # 4. 実効CAAレコード(親ドメインへの遡りの末に最初に見つかったCAA。CNAMEの参照先を含む)による許可確認
    #    ※ CAA(RFC 8659)はDCVとは別レイヤの「どのCAが発行してよいか」の許可リストであり、
    #      上位ドメインへ遡って探すのは仕様どおりの正常動作(NXDOMAINは障害にならない)。方式によらず発行を左右する。
    #    ※ 対象ドメイン自身に空でないCAAが見つかればそこで探索を打ち切るため、
    #      無関係な上位ドメインのCAAレコードが誤って判定に影響することはない
    #    ※ 3拠点で同じ実効CAAが得られた場合は、同じ指摘を3回繰り返さず1件にまとめる
    local caa_ng=0
    local rel_labels rel_domains rel_caas suffix i reason
    if [ "$rel_def" == "$rel_8888" ] && [ "$rel_8888" == "$rel_1111" ]; then
        rel_labels=("")
        rel_domains=("$rel_def_domain")
        rel_caas=("$rel_def_caa")
        suffix="(全DNS拠点で共通)"
    else
        rel_labels=("デフォルトDNSで" "8.8.8.8で" "1.1.1.1で")
        rel_domains=("$rel_def_domain" "$rel_8888_domain" "$rel_1111_domain")
        rel_caas=("$rel_def_caa" "$rel_8888_caa" "$rel_1111_caa")
        suffix=""
    fi
    for (( i=0; i<${#rel_labels[@]}; i++ )); do
        [ -z "${rel_domains[i]}" ] && continue
        reason=$(caa_denial_reason "${rel_caas[i]}")
        if [ -n "$reason" ]; then
            caa_ng=1
            fail_reasons+=("・${rel_labels[i]}実効的に適用されるCAAレコード (${rel_domains[i]}: ${rel_caas[i]}) では $CA_DOMAIN による発行が許可されていません。$suffix")
            fail_reasons+=("  [理由] $reason")
        fi
    done
    if [ $caa_ng -eq 1 ]; then
        mpic_pass=0
        csr_state=0
        acme_state=0
        fail_reasons+=("  [原因推測] CAAはDCVとは別レイヤの許可リストで、発行直前(8時間以内、ACMEではfinalize時)にCAが確認します。")
        fail_reasons+=("  [CSR申請の場合]  上位ADNでのDCVが済んでいても、CAAで拒否されるため発行できません。")
        fail_reasons+=("  [ACME発行の場合] チャレンジ検証に成功しても、finalize時のCAA確認で拒否され発行できません。")
    fi

    # 【注意】: 判定には反映しないが確認したほうがよい点
    local warnings=()
    # CSR申請が条件付き(⚠️)になったときの「発行方式別の見通し」の説明 (空なら上位ADNのDCVについての説明)
    local csr_conditional_msg=""

    # 4-2. 実効CAAレコードの RFC 8657 パラメータ (accounturi / validationmethods)
    #    BR 4.2.2.1.2 (SC-098) により、2027-03-15 からCAはこれらのパラメータの処理が必須になる。
    #    施行日より前は判定に反映せず、施行日以降に起きることを【注意】として表示する。
    local param_domain="" param_caa=""
    # CAAで許可されているACMEの方式 (施行日以降に validationmethods で限定されていれば、その方式だけになる)
    local caa_acme_allowed=$UPKI_ACME_METHODS
    if [ $caa_ng -eq 0 ]; then
        for (( i=0; i<${#rel_domains[@]}; i++ )); do
            if [ -n "${rel_domains[i]}" ]; then
                param_domain=${rel_domains[i]}
                param_caa=${rel_caas[i]}
                break
            fi
        done
    fi
    if [ -n "$param_caa" ]; then
        local effects
        effects=$(caa_parameter_effects "$param_caa")
        if [ "$(kv_get "$effects" has_params)" == "1" ]; then
            local params acme_methods acme_acct enforced=0 when
            params=$(kv_get "$effects" params)
            acme_methods=$(kv_get "$effects" acme_methods)
            acme_acct=$(kv_get "$effects" acme_acct)
            if [[ ! "$TODAY" < "$CAA_PARAMS_EFFECTIVE" ]]; then
                enforced=1
                when=""
                caa_acme_allowed=$(kv_get "$effects" acme_allowed | tr ',' ' ')
            else
                when="${CAA_PARAMS_EFFECTIVE}以降、"
            fi

            if [ "$(kv_get "$effects" csr_ok)" != "1" ]; then
                if [ $enforced -eq 1 ] && [ $csr_state -eq 1 ]; then
                    csr_state=2
                    csr_conditional_msg="実効CAAレコードのパラメータ($params)でUPKIのCSR申請が許可されるか、UPKI/CAへの確認が必要です。"
                fi
                warnings+=("・${when}CSR申請が実効CAAレコードのパラメータ ($params) で制限されます。許可されるかの確認が必要です。(ドメイン: $param_domain)")
                warnings+=("  UPKIのCSR申請でCAが使う検証方式(BR 3.2.2.4の項番号。validationmethods では ca-tbr-N と書く)や、")
                warnings+=("  ACME以外の申請での accounturi の形式は、このツールでは判定できないため、UPKI/CAに確認してください。")
            fi

            if [ "$(kv_get "$effects" acme_ok)" != "1" ]; then
                if [ $enforced -eq 1 ]; then
                    mpic_pass=0
                    acme_state=0
                    fail_reasons+=("・実効CAAレコードの validationmethods ($params) にUPKIのACMEで使える検証方式(dns-01 / http-01)が含まれないため、ACMEでは発行できません。(ドメイン: $param_domain)")
                    fail_reasons+=("  [ACME発行の場合] 2027-03-15以降、CAはvalidationmethodsの処理が必須です(BR 4.2.2.1.2、SC-098)。")
                    fail_reasons+=("                   ACMEクライアントで使う検証方式を validationmethods に追加してください。")
                else
                    warnings+=("・${when}ACMEでは発行できなくなります。実効CAAレコードの validationmethods ($params) にUPKIのACMEで使える検証方式(dns-01 / http-01)が含まれません。(ドメイン: $param_domain)")
                    warnings+=("  BR 4.2.2.1.2 (SC-098) により、${CAA_PARAMS_EFFECTIVE}からCAは validationmethods の処理が必須になります。")
                fi
            else
                if [ "$acme_methods" != "all" ]; then
                    warnings+=("・${when}ACMEで使える検証方式が validationmethods で限定されます ($acme_methods)。ACMEクライアントがこの方式で検証するか確認してください。(ドメイン: $param_domain)")
                    if [ "$(kv_get "$effects" acme_tbr_only)" == "1" ]; then
                        warnings+=("  ACMEの方式名(dns-01 など)ではなく ca-tbr-N の形で書かれています。BRは同じ方式を表すどちらの書き方も許可するよう推奨していますが、")
                        warnings+=("  必須ではないため、ACMEの方式名も併記すると確実です。")
                    fi
                fi
                if [ -n "$acme_acct" ]; then
                    warnings+=("・${when}ACMEでは accounturi で指定されたアカウント ($acme_acct) からのみ発行できます。(ドメイン: $param_domain)")
                    warnings+=("  UPKIで払い出されたACMEアカウントのURLと一致するか確認してください。")
                fi
            fi
        fi
    fi

    # 4-3. ACME向けの事前確認 (UPKIのACMEで使える dns-01 / http-01)
    #    候補の方式(--acme-method の指定、なければ dns-01 と http-01)のうち、CAAで許可され、
    #    DNSの面で使える方式が1つもなければ、ACMEでは発行できない
    local acme_usable=""
    if [ $acme_state -eq 1 ]; then
        collect_acme_info "$fqdn"
        local candidates m problem acme_problems=()
        candidates=${ACME_METHOD:-$UPKI_ACME_METHODS}
        for m in $candidates; do
            if [[ " $caa_acme_allowed " != *" $m "* ]]; then
                problem="実効CAAレコードの validationmethods で許可されていません"
            elif [ "$m" == "dns-01" ]; then
                problem=$(acme_dns01_problem)
            else
                problem=$(acme_http01_problem)
            fi
            if [ -n "$problem" ]; then
                acme_problems+=("  $m: $problem")
            else
                acme_usable="${acme_usable:+$acme_usable, }$m"
            fi
        done

        if [ -z "$acme_usable" ]; then
            mpic_pass=0
            acme_state=0
            if [ -n "$ACME_METHOD" ]; then
                fail_reasons+=("・--acme-method で指定した検証方式 ($ACME_METHOD) では、ACMEで発行できません。")
            else
                fail_reasons+=("・UPKIのACMEで使える検証方式 (dns-01 / http-01) のどちらでも、ACMEで発行できません。")
            fi
            fail_reasons+=("${acme_problems[@]}")
            fail_reasons+=("  [ACME発行の場合] dns-01 は _acme-challenge.$fqdn にTXTレコードを置ける(名前解決できる)こと、")
            fail_reasons+=("                   http-01 はCAがインターネットから80番ポートで接続できるアドレスがあることが必要です。")
        fi

        if [[ "$acme_usable" == *"dns-01"* ]] && [ "$ACME_CHAL_DANGLING" == "1" ]; then
            warnings+=("・_acme-challenge.$fqdn のCNAMEの参照先 ($ACME_CHAL_CNAME) が存在しません (NXDOMAIN)。")
            warnings+=("  dns-01 の委任先(acme-dns など)の設定が消えていないか確認してください。")
        fi
        if [[ "$acme_usable" == *"http-01"* ]]; then
            if [ -n "$ACME_PRIVATE_ADDRS" ]; then
                warnings+=("・$fqdn のアドレスにプライベートアドレス ($ACME_PRIVATE_ADDRS) が含まれています。")
                warnings+=("  CAがこのアドレスに接続すると、http-01 の検証に失敗します。")
            fi
            if [ -n "$ACME_PUBLIC_V6" ]; then
                warnings+=("・$fqdn にAAAAレコード ($ACME_PUBLIC_V6) があります。")
                warnings+=("  CAはIPv6で接続することがあるため、http-01 を使う場合はIPv6でも80番ポートで応答することを確認してください。")
            fi
        fi
    fi

    # 5. 権威DNSサーバーへの直接問い合わせ
    #    CAのDNS観測点は、どの権威DNSサーバーに問い合わせるかが観測点ごと・問い合わせごとに異なる。
    #    サーバー間で応答が食い違えば観測点間で結果が揃わず、MPICの裏付けが取れない(方式によらず発行できない)。
    #    一部のサーバーの無応答やSOAシリアルの不一致は、必ず失敗するとは限らないため【注意】として扱う。
    collect_auth_info "$fqdn"
    if [ -z "$AUTH_ZONE" ]; then
        warnings+=("・権威DNSサーバー(NSレコード)を特定できなかったため、権威DNSサーバーへの直接確認は行っていません。")
    else
        local ok_count=0 first_key="" key auth_mismatch=0 serials="" lame=() auth_lines=()
        for (( i=0; i<${#AUTH_SERVERS[@]}; i++ )); do
            if [ "${AUTH_STATUS[i]}" == "NOERROR" ] || [ "${AUTH_STATUS[i]}" == "NXDOMAIN" ]; then
                ok_count=$((ok_count + 1))
                key="${AUTH_STATUS[i]}|${AUTH_CAA[i]}|${AUTH_CNAME[i]}"
                if [ -z "$first_key" ]; then
                    first_key=$key
                elif [ "$key" != "$first_key" ]; then
                    auth_mismatch=1
                fi
                serials="$serials${AUTH_SERIAL[i]}"$'\n'
                auth_lines+=("  ${AUTH_SERVERS[i]}: status=${AUTH_STATUS[i]}, CAA='${AUTH_CAA[i]}', CNAME='${AUTH_CNAME[i]}', SOAシリアル=${AUTH_SERIAL[i]}")
            else
                lame+=("${AUTH_SERVERS[i]}: ${AUTH_STATUS[i]}")
            fi
        done

        if [ $auth_mismatch -eq 1 ]; then
            mpic_pass=0
            csr_state=0
            acme_state=0
            fail_reasons+=("・権威DNSサーバー間で応答(ステータス、CAA、CNAME)が一致しませんでした。(ゾーン: $AUTH_ZONE)")
            fail_reasons+=("${auth_lines[@]}")
            fail_reasons+=("  [原因推測] 一部の権威DNSサーバーへの設定の反映漏れや、ゾーン転送の失敗が考えられます。")
            fail_reasons+=("  [CSR申請/ACME発行に共通] CAのDNS観測点はどの権威DNSサーバーに問い合わせるかが毎回異なるため、")
            fail_reasons+=("                           観測点ごとに結果が食い違い、どちらの方式でも発行が抑制されます。")
        elif [ "$(printf '%s' "$serials" | sort -u | grep -c .)" -gt 1 ]; then
            warnings+=("・権威DNSサーバー間でSOAシリアルが一致しません。(ゾーン: $AUTH_ZONE)")
            warnings+=("${auth_lines[@]}")
            warnings+=("  今回確認したレコードは一致していますが、ゾーンの同期が遅れているか、一部のサーバーが更新されていない可能性があります。")
        fi

        if [ $ok_count -eq 0 ]; then
            warnings+=("・権威DNSサーバーのどれにも直接問い合わせできませんでした。(ゾーン: $AUTH_ZONE)")
            warnings+=("  この端末からDNS(53番ポート)への通信が制限されている可能性があります。パブリックDNSでの確認結果をご参照ください。")
        elif [ ${#lame[@]} -gt 0 ]; then
            warnings+=("・一部の権威DNSサーバーが正常に応答しません。(ゾーン: $AUTH_ZONE)")
            for (( i=0; i<${#lame[@]}; i++ )); do
                warnings+=("  ${lame[i]}")
            done
            warnings+=("  CAのDNS観測点がこのサーバーに問い合わせると時間切れや失敗になり、MPICの裏付けが取れない場合があります。")
        fi
        if [ ${#AUTH_NO_V4[@]} -gt 0 ]; then
            warnings+=("・IPv4アドレスが見つからない権威DNSサーバーがあります (${AUTH_NO_V4[*]})。IPv6での到達性は確認していません。")
        fi
    fi

    # 呼び出し元(まとめ表示)で使うため、判定結果をグローバル変数にも残す
    MPIC_CSR_STATE=$csr_state
    MPIC_ACME_STATE=$acme_state
    MPIC_REASON=""
    if [ ${#fail_reasons[@]} -gt 0 ]; then
        MPIC_REASON=${fail_reasons[0]#・}
    fi
    MPIC_WARNING=""
    if [ ${#warnings[@]} -gt 0 ]; then
        MPIC_WARNING=${warnings[0]#・}
    fi

    if [ $mpic_pass -eq 1 ]; then
        echo "判定結果: ✅ パスする可能性が高いです。"
        echo "複数のDNS拠点と権威DNSサーバーからの応答（ステータス、CAA、CNAME）が一致しています。"
    else
        echo "判定結果: ❌ パスしない（エラーになる）可能性が高いです。"
        echo "以下の原因が考えられます："
        for reason in "${fail_reasons[@]}"; do
            echo "$reason"
        done
    fi

    if [ ${#warnings[@]} -gt 0 ]; then
        echo ""
        echo "【注意】"
        for reason in "${warnings[@]}"; do
            echo "$reason"
        done
    fi

    # 発行方式ごとの見通し
    echo ""
    echo "--------------------------------------------------"
    echo "【発行方式別の見通し】"
    case $csr_state in
        1) echo "  CSR申請  : ✅ DNS/CAA面で発行を妨げる問題は見つかりませんでした。" ;;
        2)
            if [ -n "$csr_conditional_msg" ]; then
                echo "  CSR申請  : ⚠️  $csr_conditional_msg"
            else
                echo "  CSR申請  : ⚠️  上位ADNでDCV済み(200日以内)かつCAAが適切であれば発行され得ます。UPKI/CAへの確認を推奨します。"
            fi
            ;;
        0) echo "  CSR申請  : ❌ 発行できない可能性が高いです。" ;;
    esac
    case $acme_state in
        1) echo "  ACME発行 : ✅ DNS/CAA面で発行を妨げる問題は見つかりませんでした。(使える検証方式: $acme_usable)" ;;
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

    echo ""
    echo "=================================================="
    echo "権威DNSサーバーでの確認 (再帰なしで直接問い合わせ)"
    echo "=================================================="
    print_auth_info "$target"

    echo ""
    echo "=================================================="
    echo "ACME向けの事前確認 (UPKIのACMEで使える dns-01 / http-01)"
    echo "=================================================="
    print_acme_info "$target"

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
                hosts+=("$(to_lower "$col11")")
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
                [ $dup -eq 0 ] && hosts+=("$(to_lower "$host")")
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
CHECKED_WARNING=()

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
    CHECKED_WARNING+=("$MPIC_WARNING")
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
    elif [ -n "${CHECKED_WARNING[idx]}" ]; then
        line="$line  ← 注意: ${CHECKED_WARNING[idx]}"
    fi
    echo "$line"
}

# 確認したすべてのFQDNのうち最も悪い結果から終了コードを決める
# (CSR / ACME のどちらかが ❌ なら EXIT_CRITICAL とする)
overall_exit_code() {
    local i code=$EXIT_OK
    for (( i=0; i<${#CHECKED_FQDNS[@]}; i++ )); do
        if [ "${CHECKED_CSR[i]}" == "0" ] || [ "${CHECKED_ACME[i]}" == "0" ]; then
            echo $EXIT_CRITICAL
            return
        fi
        if [ "${CHECKED_CSR[i]}" == "2" ] || [ "${CHECKED_ACME[i]}" == "2" ] || [ -n "${CHECKED_WARNING[i]}" ]; then
            code=$EXIT_WARNING
        fi
    done
    echo $code
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
        local row_note=""
        local n=0
        for host in ${ROW_HOSTS[r]}; do
            idx=$(find_checked "$host")
            row_csr=$(worse_state "$row_csr" "${CHECKED_CSR[idx]}")
            row_acme=$(worse_state "$row_acme" "${CHECKED_ACME[idx]}")
            [ -n "${CHECKED_WARNING[idx]}" ] && row_note="  (注意あり)"
            n=$((n + 1))
        done

        local cn=${ROW_CNS[r]}
        [ -z "$cn" ] && cn="(利用管理者FQDN未記入)"
        echo ""
        echo "行${ROW_LINES[r]}  CN=$cn  (ホスト名${n}件)  CSR: $(state_mark "$row_csr")  ACME: $(state_mark "$row_acme")$row_note"
        for host in ${ROW_HOSTS[r]}; do
            print_host_result "$host" "    - "
        done
    done

    echo ""
    echo "--------------------------------------------------"
    echo "※ 1枚の証明書(ACMEでは1回のorder)に含まれるホスト名が1つでも発行できない場合は申請全体が失敗するため、"
    echo "  行の判定は最も悪いホスト名の結果に合わせています。"
    echo "※ ⚠️  は、上位ADNでDCV済み(200日以内)かつCAAが適切であれば発行され得る状態か、"
    echo "  CAAのパラメータ(accounturi / validationmethods)でCSR申請が許可されるかUPKI/CAへの確認が必要な状態です。"
    echo "※ (注意あり) は、判定には影響しないものの、権威DNSサーバーの応答などに確認したほうがよい点がある状態です。"
    if [ $QUIET -eq 1 ]; then
        echo "※ 原因の詳細は -q を付けずに実行した個別の確認ログを参照してください。"
    fi
    echo "--------------------------------------------------"
}

main() {
    parse_args "$@"
    ensure_psl

    # --update-psl だけを指定した場合は、取り直したところで終了する
    if [ -z "$TARGET_FQDN" ] && [ -z "$TSV_FILE" ]; then
        exit $EXIT_OK
    fi

    local r host
    if [ -n "$TSV_FILE" ]; then
        echo "--> 申請TSV ($TSV_FILE) を読み込みます"
        parse_tsv "$TSV_FILE"
        if [ ${#ROW_LINES[@]} -eq 0 ]; then
            echo "確認対象のホスト名がTSVに見つかりませんでした。"
            exit $EXIT_ERROR
        fi

        for (( r=0; r<${#ROW_LINES[@]}; r++ )); do
            for host in ${ROW_HOSTS[r]}; do
                run_check "$host" "行${ROW_LINES[r]}"
            done
        done

        print_tsv_summary
    else
        if ! is_valid_hostname "$TARGET_FQDN"; then
            echo "「${TARGET_FQDN}」はFQDNの形式ではありません。URLではなくホスト名だけを指定してください。(例: www.example.ac.jp)"
            exit $EXIT_ERROR
        fi
        run_check "$TARGET_FQDN" ""
        if [ $QUIET -eq 1 ]; then
            print_host_result "$TARGET_FQDN" ""
        fi
    fi

    exit "$(overall_exit_code)"
}

# テストから source された場合は関数の定義だけを読み込み、実行はしない
if [ "${BASH_SOURCE[0]}" == "$0" ]; then
    main "$@"
fi
