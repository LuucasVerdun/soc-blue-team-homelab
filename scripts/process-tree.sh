#!/usr/bin/env bash

# ============================================================
# SOC PROCESS TREE
# Wazuh + Sysmon Investigation Helper
#
# MODOS:
#
# Por ProcessGuid:
#   ./process-tree.sh '{PROCESS-GUID}'
#   ./process-tree.sh '{PROCESS-GUID}' --summary
#   ./process-tree.sh '{PROCESS-GUID}' --report
#
# Por Rule ID:
#   ./process-tree.sh --rule 100130
#   ./process-tree.sh --rule 100130 --summary
#   ./process-tree.sh --rule 100130 --report
#
# Histórico:
#   ./process-tree.sh --rule 100130 --days 7 --summary
#   ./process-tree.sh --rule 100130 --days 7 --report
#
# ============================================================


# ============================================================
# CONFIGURAÇÃO
# ============================================================

ALERT_ROOT="/var/ossec/logs/alerts"

START_GUID=""
RULE_ID=""

SUMMARY=false
REPORT=false

DAYS=7
MAX_DEPTH=10

SNAPSHOT=""


# ============================================================
# AJUDA
# ============================================================

usage() {

    echo
    echo "SOC Process Tree - Wazuh + Sysmon"
    echo
    echo "Uso:"
    echo
    echo "  $0 '{PROCESS-GUID}'"
    echo "  $0 '{PROCESS-GUID}' --summary"
    echo "  $0 '{PROCESS-GUID}' --report"
    echo
    echo "  $0 --rule RULE_ID"
    echo "  $0 --rule RULE_ID --summary"
    echo "  $0 --rule RULE_ID --report"
    echo
    echo "  $0 --rule RULE_ID --days N --summary"
    echo "  $0 --rule RULE_ID --days N --report"
    echo
    echo "Opções:"
    echo
    echo "  --rule ID       Último alerta da Rule informada"
    echo "  --days N        Pesquisa os últimos N dias"
    echo "                  Padrão: 7"
    echo
    echo "  --summary       Exibe árvore resumida"
    echo "  --report        Gera relatório de triagem SOC"
    echo "  -h, --help      Mostra esta ajuda"
    echo
}


# ============================================================
# LIMPEZA VISUAL
# ============================================================

clean() {

    printf '%s' "$1" |
        sed \
            -e 's/\\\\/\\/g' \
            -e 's/\\"/"/g' \
            -e 's/&amp;/\&/g' \
            -e 's/&quot;/"/g'
}


short_name() {

    local value

    value=$(clean "$1")

    printf '%s\n' "$value" |
        sed 's#^.*\\##'
}


# ============================================================
# ARGUMENTOS
# ============================================================

while [ "$#" -gt 0 ]; do

    case "$1" in

        --rule)

            if [ -z "${2:-}" ]; then
                echo "[!] Informe o Rule ID."
                exit 1
            fi

            RULE_ID="$2"

            shift 2
            ;;


        --days)

            if [ -z "${2:-}" ]; then
                echo "[!] Informe a quantidade de dias."
                exit 1
            fi

            if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                echo "[!] --days precisa ser um número inteiro."
                exit 1
            fi

            if [ "$2" -lt 1 ]; then
                echo "[!] --days precisa ser maior que zero."
                exit 1
            fi

            DAYS="$2"

            shift 2
            ;;


        --summary)

            SUMMARY=true

            shift
            ;;


        --report)

            REPORT=true

            shift
            ;;


        -h|--help)

            usage

            exit 0
            ;;


        -*)

            echo
            echo "[!] Opção desconhecida: $1"

            usage

            exit 1
            ;;


        *)

            if [ -z "$START_GUID" ]; then

                START_GUID="$1"

                shift

            else

                echo
                echo "[!] Argumento desconhecido: $1"

                usage

                exit 1

            fi
            ;;

    esac

done


# ============================================================
# VALIDAÇÃO DOS ARGUMENTOS
# ============================================================

if [ -n "$START_GUID" ] && [ -n "$RULE_ID" ]; then

    echo
    echo "[!] Escolha apenas um método:"
    echo
    echo "    ProcessGuid"
    echo "       OU"
    echo "    --rule"
    echo

    exit 1
fi


if [ -z "$START_GUID" ] && [ -z "$RULE_ID" ]; then

    usage

    exit 1
fi


if [ "$SUMMARY" = true ] && [ "$REPORT" = true ]; then

    echo
    echo "[!] Escolha apenas um modo:"
    echo
    echo "    --summary"
    echo "       OU"
    echo "    --report"
    echo

    exit 1
fi


# ============================================================
# ACESSO AO WAZUH
# ============================================================

sudo -v || exit 1


if ! sudo test -d "$ALERT_ROOT"; then

    echo
    echo "[!] Diretório do Wazuh não encontrado:"
    echo
    echo "    $ALERT_ROOT"
    echo

    exit 1
fi


# ============================================================
# SNAPSHOT
#
# Criamos uma cópia temporária dos alertas.
#
# Isso evita inconsistência caso o Wazuh escreva novos
# eventos enquanto fazemos a investigação.
# ============================================================

SNAPSHOT=$(mktemp)

trap 'rm -f "$SNAPSHOT"' EXIT


build_snapshot() {

    local count=0

    while IFS= read -r file; do

        [ -z "$file" ] && continue

        sudo cat "$file" >> "$SNAPSHOT"

        printf '\n' >> "$SNAPSHOT"

        count=$((count + 1))

    done < <(

        sudo find "$ALERT_ROOT" \
            -type f \
            \( \
                -name 'alerts.json' \
                -o \
                -name 'ossec-alerts-*.json' \
            \) \
            -mtime "-${DAYS}" \
            -print 2>/dev/null |
            sort
    )


    if [ "$count" -eq 0 ]; then

        echo
        echo "[!] Nenhum arquivo de alerta encontrado."
        echo
        echo "    Janela: últimos $DAYS dias"
        echo

        exit 1
    fi
}


build_snapshot


# ============================================================
# CONTROLE DE RECURSÃO
# ============================================================

declare -A VISITED


# ============================================================
# LOCALIZAR EVENTO PELO PROCESSGUID
#
# Se houver vários alertas para o mesmo processo, escolhemos
# o evento com maior nível de severidade.
# ============================================================

get_event() {

    local guid="$1"

    [ -z "$guid" ] && return


    jq -Rrc --arg guid "$guid" '

        fromjson?

        |

        select(
            .data.win.eventdata.processGuid? == $guid
        )

    ' "$SNAPSHOT" |

    jq -s -c '

        if length == 0 then

            empty

        else

            max_by([
                (.rule.level // 0),
                (.timestamp // "")
            ])

        end

    '
}


# ============================================================
# LOCALIZAR PROCESSOS FILHOS
# ============================================================

get_children() {

    local guid="$1"

    [ -z "$guid" ] && return


    jq -Rr --arg guid "$guid" '

        fromjson?

        |

        select(
            .data.win.eventdata.parentProcessGuid? == $guid
        )

        |

        .data.win.eventdata.processGuid? // empty

    ' "$SNAPSHOT" |

    grep -v '^$' |

    sort -u
}


# ============================================================
# LOCALIZAR ÚLTIMO ALERTA DE UMA RULE
# ============================================================

get_latest_rule_event() {

    local rule="$1"


    jq -Rrc --arg rule "$rule" '

        fromjson?

        |

        select(
            (.rule.id? | tostring) == $rule
        )

    ' "$SNAPSHOT" |

    jq -s -c '

        if length == 0 then

            empty

        else

            max_by(.timestamp // "")

        end

    '
}


# ============================================================
# RULE ID -> PROCESSGUID
# ============================================================

if [ -n "$RULE_ID" ]; then

    RULE_EVENT=$(get_latest_rule_event "$RULE_ID")


    if [ -z "$RULE_EVENT" ]; then

        echo
        echo "[!] Nenhum alerta encontrado para Rule:"
        echo
        echo "    $RULE_ID"
        echo
        echo "    Janela pesquisada: $DAYS dias"
        echo

        exit 1
    fi


    START_GUID=$(echo "$RULE_EVENT" |
        jq -r '.data.win.eventdata.processGuid // empty')


    if [ -z "$START_GUID" ]; then

        echo
        echo "[!] O alerta da Rule $RULE_ID"
        echo "    não possui ProcessGuid."
        echo

        exit 1
    fi
fi


# ============================================================
# EVENTO PRINCIPAL
# ============================================================

CURRENT=$(get_event "$START_GUID")


if [ -z "$CURRENT" ]; then

    echo
    echo "[!] ProcessGuid não encontrado:"
    echo
    echo "    $START_GUID"
    echo
    echo "    Janela pesquisada: $DAYS dias"
    echo

    exit 1
fi


# ============================================================
# CAMPOS DO ALERTA PRINCIPAL
# ============================================================

CURRENT_RULE=$(echo "$CURRENT" |
    jq -r '.rule.id // "N/A"')


CURRENT_LEVEL=$(echo "$CURRENT" |
    jq -r '.rule.level // "N/A"')


CURRENT_DESCRIPTION=$(echo "$CURRENT" |
    jq -r '.rule.description // "N/A"')


CURRENT_HOST=$(echo "$CURRENT" |
    jq -r '.agent.name // .data.win.system.computer // "N/A"')


CURRENT_IP=$(echo "$CURRENT" |
    jq -r '.agent.ip // "N/A"')


CURRENT_USER=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.user // "N/A"')


CURRENT_TIMESTAMP=$(echo "$CURRENT" |
    jq -r '.timestamp // "N/A"')


CURRENT_IMAGE=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.image // "N/A"')


CURRENT_COMMAND=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.commandLine // "N/A"')


CURRENT_INTEGRITY=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.integrityLevel // "N/A"')


CURRENT_HASHES=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.hashes // "N/A"')


# Limpeza visual

CURRENT_DESCRIPTION=$(clean "$CURRENT_DESCRIPTION")
CURRENT_USER=$(clean "$CURRENT_USER")
CURRENT_IMAGE=$(clean "$CURRENT_IMAGE")
CURRENT_COMMAND=$(clean "$CURRENT_COMMAND")
CURRENT_HASHES=$(clean "$CURRENT_HASHES")


# ============================================================
# PROCESSO PAI
# ============================================================

PARENT_GUID=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.parentProcessGuid // empty')


PARENT_IMAGE=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.parentImage // "N/A"')


PARENT_COMMAND=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.parentCommandLine // "N/A"')


PARENT_USER=$(echo "$CURRENT" |
    jq -r '.data.win.eventdata.parentUser // "N/A"')


PARENT_IMAGE=$(clean "$PARENT_IMAGE")
PARENT_COMMAND=$(clean "$PARENT_COMMAND")
PARENT_USER=$(clean "$PARENT_USER")


# ============================================================
# EXIBIÇÃO COMPLETA DE UM PROCESSO
# ============================================================

show_process_full() {

    local guid="$1"
    local prefix="$2"
    local is_last="$3"

    local connector
    local continuation


    if [ "$is_last" -eq 1 ]; then

        connector="└── "
        continuation="${prefix}    "

    else

        connector="├── "
        continuation="${prefix}│   "

    fi


    local event

    event=$(get_event "$guid")


    if [ -z "$event" ]; then

        echo "${prefix}${connector}[Processo não encontrado]"
        echo "${continuation}GUID: $guid"

        return
    fi


    local image
    local command
    local rule
    local level
    local description
    local user
    local integrity
    local hashes
    local timestamp


    image=$(echo "$event" |
        jq -r '.data.win.eventdata.image // "N/A"')


    command=$(echo "$event" |
        jq -r '.data.win.eventdata.commandLine // "N/A"')


    rule=$(echo "$event" |
        jq -r '.rule.id // "N/A"')


    level=$(echo "$event" |
        jq -r '.rule.level // "N/A"')


    description=$(echo "$event" |
        jq -r '.rule.description // "N/A"')


    user=$(echo "$event" |
        jq -r '.data.win.eventdata.user // "N/A"')


    integrity=$(echo "$event" |
        jq -r '.data.win.eventdata.integrityLevel // "N/A"')


    hashes=$(echo "$event" |
        jq -r '.data.win.eventdata.hashes // "N/A"')


    timestamp=$(echo "$event" |
        jq -r '.timestamp // "N/A"')


    image=$(clean "$image")
    command=$(clean "$command")
    description=$(clean "$description")
    user=$(clean "$user")
    hashes=$(clean "$hashes")


    echo "${prefix}${connector}${image}"

    echo "${continuation}├─ CommandLine: $command"

    echo "${continuation}├─ Rule: $rule | Level: $level"

    echo "${continuation}├─ Description: $description"

    echo "${continuation}├─ User: $user"

    echo "${continuation}├─ Integrity: $integrity"

    echo "${continuation}├─ Timestamp: $timestamp"

    echo "${continuation}├─ Hashes: $hashes"

    echo "${continuation}└─ GUID: $guid"
}


# ============================================================
# EXIBIÇÃO RESUMIDA
# ============================================================

show_process_summary() {

    local guid="$1"
    local prefix="$2"
    local is_last="$3"

    local connector


    if [ "$is_last" -eq 1 ]; then

        connector="└── "

    else

        connector="├── "

    fi


    local event

    event=$(get_event "$guid")


    if [ -z "$event" ]; then

        echo "${prefix}${connector}[Processo não encontrado]"

        return
    fi


    local image
    local rule
    local level


    image=$(echo "$event" |
        jq -r '.data.win.eventdata.image // "N/A"')


    rule=$(echo "$event" |
        jq -r '.rule.id // "N/A"')


    level=$(echo "$event" |
        jq -r '.rule.level // "N/A"')


    image=$(short_name "$image")


    echo "${prefix}${connector}${image} [Rule $rule | L$level]"
}


# ============================================================
# RECURSÃO DA ÁRVORE
# ============================================================

walk_tree() {

    local guid="$1"
    local prefix="$2"
    local is_last="$3"
    local depth="$4"


    [ -z "$guid" ] && return


    if [ "$depth" -gt "$MAX_DEPTH" ]; then

        echo "${prefix}[!] Profundidade máxima atingida."

        return
    fi


    if [[ -n "${VISITED[$guid]+x}" ]]; then

        return
    fi


    VISITED["$guid"]=1


    if [ "$SUMMARY" = true ]; then

        show_process_summary \
            "$guid" \
            "$prefix" \
            "$is_last"

    else

        show_process_full \
            "$guid" \
            "$prefix" \
            "$is_last"

    fi


    local next_prefix


    if [ "$is_last" -eq 1 ]; then

        next_prefix="${prefix}    "

    else

        next_prefix="${prefix}│   "

    fi


    local children=()


    while IFS= read -r child; do

        [ -z "$child" ] && continue

        children+=("$child")

    done < <(get_children "$guid")


    local count="${#children[@]}"
    local i


    for ((i=0; i<count; i++)); do

        local child="${children[$i]}"

        local child_is_last=0


        if [ "$i" -eq $((count - 1)) ]; then

            child_is_last=1

        fi


        walk_tree \
            "$child" \
            "$next_prefix" \
            "$child_is_last" \
            $((depth + 1))

    done
}


# ============================================================
# MODO --REPORT
# ============================================================

if [ "$REPORT" = true ]; then

    MITRE_LINES=$(echo "$CURRENT" |
        jq -r '

            (.rule.mitre.id // []) as $ids

            |

            (.rule.mitre.technique // []) as $techniques

            |

            range(0; ($ids | length)) as $i

            |

            "\($ids[$i])  \($techniques[$i] // "N/A")"

        ')


    echo
    echo "============================================================"
    echo "                    SOC TRIAGE REPORT"
    echo "============================================================"
    echo


    echo "[ALERT]"

    echo "Rule ID:      $CURRENT_RULE"

    echo "Level:        $CURRENT_LEVEL"

    echo "Host:         $CURRENT_HOST"

    echo "IP:           $CURRENT_IP"

    echo "User:         $CURRENT_USER"

    echo "Timestamp:    $CURRENT_TIMESTAMP"

    echo "ProcessGuid:  $START_GUID"

    echo "Window:       últimos $DAYS dias"


    echo
    echo "[DETECTION]"

    echo "$CURRENT_DESCRIPTION"


    echo
    echo "[MITRE ATT&CK]"


    if [ -n "$MITRE_LINES" ]; then

        echo "$MITRE_LINES"

    else

        echo "N/A"

    fi


    echo
    echo "[PROCESS]"


    echo "Image:"

    echo "$CURRENT_IMAGE"


    echo
    echo "Parent:"

    echo "$PARENT_IMAGE"


    echo
    echo "Parent GUID:"

    echo "$PARENT_GUID"


    echo
    echo "User:"

    echo "$CURRENT_USER"


    echo
    echo "Integrity:"

    echo "$CURRENT_INTEGRITY"


    echo
    echo "CommandLine:"

    echo "$CURRENT_COMMAND"


    echo
    echo "Hashes:"

    echo "$CURRENT_HASHES"


    echo
    echo "[PROCESS TREE]"
    echo


    PARENT_SHORT=$(short_name "$PARENT_IMAGE")

    echo "$PARENT_SHORT"


    # Para o relatório queremos a árvore compacta

    SUMMARY=true


    walk_tree \
        "$START_GUID" \
        "" \
        1 \
        0


    echo
    echo "[ANALYST ASSESSMENT]"

    echo "Classification: PENDING"

    echo "Disposition:    PENDING"

    echo "Notes:          PENDING"


    echo
    echo "============================================================"
    echo "Report generated."
    echo "============================================================"
    echo


    exit 0
fi


# ============================================================
# MODO --SUMMARY
# ============================================================

if [ "$SUMMARY" = true ]; then

    echo
    echo "============================================================"
    echo "                SOC PROCESS TREE - SUMMARY"
    echo "============================================================"
    echo


    echo "[ALERT]"

    echo "Rule:        $CURRENT_RULE"

    echo "Level:       $CURRENT_LEVEL"

    echo "Description: $CURRENT_DESCRIPTION"

    echo "Host:        $CURRENT_HOST"

    echo "IP:          $CURRENT_IP"

    echo "User:        $CURRENT_USER"

    echo "Timestamp:   $CURRENT_TIMESTAMP"

    echo "ProcessGuid: $START_GUID"

    echo "Window:      últimos $DAYS dias"


    echo
    echo "[PROCESS TREE]"
    echo


    PARENT_SHORT=$(short_name "$PARENT_IMAGE")

    echo "$PARENT_SHORT"


    walk_tree \
        "$START_GUID" \
        "" \
        1 \
        0


    echo
    echo "============================================================"
    echo


    exit 0
fi


# ============================================================
# MODO COMPLETO
# ============================================================

echo
echo "================================================================"
echo "                    PROCESS TREE - SOC LAB"
echo "================================================================"
echo


echo "ALERTA BASE"

echo "  Rule:        $CURRENT_RULE"

echo "  Level:       $CURRENT_LEVEL"

echo "  Description: $CURRENT_DESCRIPTION"

echo "  Host:        $CURRENT_HOST"

echo "  IP:          $CURRENT_IP"

echo "  User:        $CURRENT_USER"

echo "  Timestamp:   $CURRENT_TIMESTAMP"

echo "  Window:      últimos $DAYS dias"


echo
echo "PROCESSO PAI"

echo "  Image:       $PARENT_IMAGE"

echo "  CommandLine: $PARENT_COMMAND"

echo "  User:        $PARENT_USER"

echo "  GUID:        $PARENT_GUID"


echo
echo "                              ↓"

echo
echo "ÁRVORE A PARTIR DO PROCESSO INVESTIGADO"
echo


walk_tree \
    "$START_GUID" \
    "" \
    1 \
    0


echo
echo "================================================================"
echo "Investigação concluída."
echo "================================================================"
echo

