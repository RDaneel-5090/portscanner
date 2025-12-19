#!/bin/bash

#===============================================================================
#
#          FILE: portscan.sh
#
#         USAGE: ./portscan.sh -h <host> [OPTIONS]
#
#   DESCRIPTION: Scanner de ports réseau en Bash
#                Permet de vérifier si des ports sont ouverts sur une machine
#                cible. Utile pour l'audit de sécurité et le diagnostic réseau.
#
#       OPTIONS: Voir la fonction show_help() ou lancer avec -H
#
#  REQUIREMENTS: bash 4+, timeout (coreutils)
#
#        AUTHOR: RDaneel-5090
#       VERSION: 1.0.0
#       CREATED: 2025
#
#===============================================================================

#===============================================================================
# CONFIGURATION & VARIABLES GLOBALES
#===============================================================================

# Version du script
readonly VERSION="1.0.0"

# Couleurs pour l'affichage (améliore la lisibilité)
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color (reset)

# Variables par défaut
HOST=""                    # Hôte cible à scanner
PORTS=""                   # Liste des ports à scanner
PORT_START=""              # Début de la plage de ports
PORT_END=""                # Fin de la plage de ports
TIMEOUT_DELAY=1            # Délai d'attente par port (en secondes)
VERBOSE=false              # Mode verbeux activé/désactivé
OUTPUT_FILE=""             # Fichier de sortie pour les résultats
SCAN_MODE="list"           # Mode de scan: "list" ou "range"

# Compteurs pour les statistiques
PORTS_OPEN=0
PORTS_CLOSED=0
PORTS_SCANNED=0

# Ports communs avec leurs services associés (pour l'affichage informatif)
declare -A COMMON_PORTS=(
    [21]="FTP"
    [22]="SSH"
    [23]="Telnet"
    [25]="SMTP"
    [53]="DNS"
    [80]="HTTP"
    [110]="POP3"
    [143]="IMAP"
    [443]="HTTPS"
    [445]="SMB"
    [993]="IMAPS"
    [995]="POP3S"
    [3306]="MySQL"
    [3389]="RDP"
    [5432]="PostgreSQL"
    [6379]="Redis"
    [8080]="HTTP-Proxy"
    [8443]="HTTPS-Alt"
    [27017]="MongoDB"
)

#===============================================================================
# FONCTIONS
#===============================================================================

#---------------------------------------
# Affiche l'aide du script
# Arguments: Aucun
# Returns: Aucun (exit 0)
#---------------------------------------
show_help() {
    cat << EOF
${CYAN}╔══════════════════════════════════════════════════════════════════╗
║                    PORT SCANNER v${VERSION}                          ║
╚══════════════════════════════════════════════════════════════════╝${NC}

${YELLOW}DESCRIPTION:${NC}
    Scanner de ports réseau en Bash. Vérifie si des ports TCP sont
    ouverts sur une machine cible.

${YELLOW}USAGE:${NC}
    ./portscan.sh -h <host> -p <ports>       Scanner des ports spécifiques
    ./portscan.sh -h <host> -r <start-end>   Scanner une plage de ports

${YELLOW}OPTIONS:${NC}
    -h, --host <hostname>    Hôte cible (IP ou nom de domaine) [REQUIS]
    -p, --ports <ports>      Liste de ports séparés par des virgules
                             Exemple: -p 22,80,443,8080
    -r, --range <start-end>  Plage de ports à scanner
                             Exemple: -r 1-1000
    -t, --timeout <seconds>  Délai d'attente par port (défaut: 1s)
    -o, --output <file>      Sauvegarder les résultats dans un fichier
    -v, --verbose            Mode verbeux (affiche plus de détails)
    -H, --help               Affiche cette aide
    -V, --version            Affiche la version du script

${YELLOW}EXEMPLES:${NC}
    # Scanner les ports web classiques sur google.com
    ./portscan.sh -h google.com -p 80,443

    # Scanner les 100 premiers ports sur une IP locale
    ./portscan.sh -h 192.168.1.1 -r 1-100 -v

    # Scanner avec sauvegarde des résultats
    ./portscan.sh -h example.com -p 22,80,443 -o results.txt

    # Scanner rapide avec timeout réduit
    ./portscan.sh -h 10.0.0.1 -r 1-1000 -t 0.5

${YELLOW}CODES DE RETOUR:${NC}
    0 - Succès (au moins un port ouvert trouvé)
    1 - Erreur (argument invalide, hôte inaccessible, etc.)
    2 - Aucun port ouvert trouvé

${YELLOW}AUTEUR:${NC}
    RDaneel-5090 - https://github.com/RDaneel-5090

EOF
    exit 0
}

#---------------------------------------
# Affiche la version du script
# Arguments: Aucun
# Returns: Aucun (exit 0)
#---------------------------------------
show_version() {
    echo "Port Scanner version ${VERSION}"
    exit 0
}

#---------------------------------------
# Affiche un message d'erreur et quitte
# Arguments:
#   $1 - Message d'erreur à afficher
# Returns: Aucun (exit 1)
#---------------------------------------
error_exit() {
    echo -e "${RED}[ERREUR]${NC} $1" >&2
    exit 1
}

#---------------------------------------
# Affiche un message de warning
# Arguments:
#   $1 - Message de warning
# Returns: Aucun
#---------------------------------------
warning() {
    echo -e "${YELLOW}[ATTENTION]${NC} $1" >&2
}

#---------------------------------------
# Affiche un message en mode verbose
# Arguments:
#   $1 - Message à afficher
# Returns: Aucun
#---------------------------------------
log_verbose() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${BLUE}[INFO]${NC} $1"
    fi
}

#---------------------------------------
# Valide qu'un port est dans la plage valide (1-65535)
# Arguments:
#   $1 - Numéro de port à valider
# Returns:
#   0 si valide, 1 sinon
#---------------------------------------
validate_port() {
    local port="$1"
    
    # Vérifie que c'est un nombre
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # Vérifie la plage valide
    if [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
        return 1
    fi
    
    return 0
}

#---------------------------------------
# Valide le format de l'hôte
# Arguments:
#   $1 - Hôte à valider
# Returns:
#   0 si valide, 1 sinon
#---------------------------------------
validate_host() {
    local host="$1"
    
    # Vérifie que l'hôte n'est pas vide
    if [[ -z "$host" ]]; then
        return 1
    fi
    
    # Vérifie qu'il ne contient pas de caractères dangereux
    if [[ "$host" =~ [[:space:]\;\|\&\$] ]]; then
        return 1
    fi
    
    return 0
}

#---------------------------------------
# Récupère le nom du service associé à un port
# Arguments:
#   $1 - Numéro de port
# Returns:
#   Nom du service ou "unknown"
#---------------------------------------
get_service_name() {
    local port="$1"
    
    if [[ -n "${COMMON_PORTS[$port]}" ]]; then
        echo "${COMMON_PORTS[$port]}"
    else
        echo "unknown"
    fi
}

#---------------------------------------
# Scanne un port unique sur l'hôte cible
# Arguments:
#   $1 - Hôte cible
#   $2 - Port à scanner
# Returns:
#   0 si le port est ouvert, 1 sinon
#---------------------------------------
scan_port() {
    local host="$1"
    local port="$2"
    local result
    
    # Utilise /dev/tcp pour tester la connexion
    # timeout évite les blocages sur les ports filtrés
    timeout "$TIMEOUT_DELAY" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null
    result=$?
    
    return $result
}

#---------------------------------------
# Affiche le résultat du scan d'un port
# Arguments:
#   $1 - Port scanné
#   $2 - Statut (open/closed)
# Returns: Aucun
#---------------------------------------
display_result() {
    local port="$1"
    local status="$2"
    local service
    local output_line
    
    service=$(get_service_name "$port")
    
    case "$status" in
        "open")
            output_line=$(printf "  %-8s %-12s %s" "$port" "${GREEN}OPEN${NC}" "($service)")
            echo -e "$output_line"
            
            # Sauvegarde dans le fichier si demandé
            if [[ -n "$OUTPUT_FILE" ]]; then
                echo "$port open $service" >> "$OUTPUT_FILE"
            fi
            ;;
        "closed")
            # N'affiche les ports fermés qu'en mode verbose
            if [[ "$VERBOSE" == true ]]; then
                output_line=$(printf "  %-8s %-12s %s" "$port" "${RED}CLOSED${NC}" "($service)")
                echo -e "$output_line"
            fi
            
            if [[ -n "$OUTPUT_FILE" ]] && [[ "$VERBOSE" == true ]]; then
                echo "$port closed $service" >> "$OUTPUT_FILE"
            fi
            ;;
    esac
}

#---------------------------------------
# Affiche une barre de progression
# Arguments:
#   $1 - Valeur actuelle
#   $2 - Valeur maximale
# Returns: Aucun
#---------------------------------------
show_progress() {
    local current="$1"
    local total="$2"
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))
    
    # Construit la barre de progression
    printf "\r  Progress: ["
    printf "%${filled}s" | tr ' ' '='
    printf "%${empty}s" | tr ' ' ' '
    printf "] %3d%% (%d/%d)" "$percent" "$current" "$total"
}

#---------------------------------------
# Exécute le scan principal
# Arguments: Aucun (utilise les variables globales)
# Returns:
#   0 si des ports ouverts trouvés, 2 sinon
#---------------------------------------
run_scan() {
    local ports_to_scan=()
    local total_ports
    local current=0
    
    # Construit la liste des ports selon le mode
    case "$SCAN_MODE" in
        "list")
            # Convertit la liste CSV en tableau
            IFS=',' read -ra ports_to_scan <<< "$PORTS"
            ;;
        "range")
            # Génère la plage de ports
            for ((port=PORT_START; port<=PORT_END; port++)); do
                ports_to_scan+=("$port")
            done
            ;;
    esac
    
    total_ports=${#ports_to_scan[@]}
    
    # Affiche l'en-tête du scan
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                      SCAN EN COURS                               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${YELLOW}Cible:${NC}    $HOST"
    echo -e "  ${YELLOW}Ports:${NC}    $total_ports port(s) à scanner"
    echo -e "  ${YELLOW}Timeout:${NC}  ${TIMEOUT_DELAY}s par port"
    echo ""
    echo -e "  ${YELLOW}PORT     STATUT       SERVICE${NC}"
    echo "  ────────────────────────────────────"
    
    # Initialise le fichier de sortie si demandé
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "# Port Scan Results - $(date)" > "$OUTPUT_FILE"
        echo "# Host: $HOST" >> "$OUTPUT_FILE"
        echo "# Ports scanned: $total_ports" >> "$OUTPUT_FILE"
        echo "#" >> "$OUTPUT_FILE"
    fi
    
    # Boucle principale de scan
    for port in "${ports_to_scan[@]}"; do
        ((current++))
        ((PORTS_SCANNED++))
        
        # Valide le port avant de scanner
        if ! validate_port "$port"; then
            warning "Port invalide ignoré: $port"
            continue
        fi
        
        log_verbose "Scan du port $port..."
        
        # Effectue le scan
        if scan_port "$HOST" "$port"; then
            ((PORTS_OPEN++))
            display_result "$port" "open"
        else
            ((PORTS_CLOSED++))
            display_result "$port" "closed"
        fi
        
        # Affiche la progression en mode non-verbose pour les gros scans
        if [[ "$VERBOSE" == false ]] && [[ $total_ports -gt 20 ]]; then
            show_progress "$current" "$total_ports"
        fi
    done
    
    # Efface la ligne de progression
    if [[ "$VERBOSE" == false ]] && [[ $total_ports -gt 20 ]]; then
        echo ""
    fi
    
    # Affiche le résumé
    echo ""
    echo "  ────────────────────────────────────"
    echo -e "  ${CYAN}RÉSUMÉ:${NC}"
    echo -e "    Ports scannés: $PORTS_SCANNED"
    echo -e "    Ports ouverts: ${GREEN}$PORTS_OPEN${NC}"
    echo -e "    Ports fermés:  ${RED}$PORTS_CLOSED${NC}"
    echo ""
    
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "  ${GREEN}✓${NC} Résultats sauvegardés dans: $OUTPUT_FILE"
        echo ""
    fi
    
    # Retourne le code approprié
    if [[ $PORTS_OPEN -gt 0 ]]; then
        return 0
    else
        return 2
    fi
}

#---------------------------------------
# Vérifie que l'hôte est accessible
# Arguments:
#   $1 - Hôte à vérifier
# Returns:
#   0 si accessible, 1 sinon
#---------------------------------------
check_host_reachable() {
    local host="$1"
    
    log_verbose "Vérification de l'accessibilité de $host..."
    
    # Essaie de résoudre le nom d'hôte
    if ! host "$host" &>/dev/null && ! ping -c 1 -W 2 "$host" &>/dev/null; then
        return 1
    fi
    
    return 0
}

#===============================================================================
# PARSING DES ARGUMENTS
#===============================================================================

parse_arguments() {
    # Vérifie qu'il y a des arguments
    if [[ $# -eq 0 ]]; then
        show_help
    fi
    
    # Parse les arguments avec getopts style long
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--host)
                if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                    error_exit "L'option -h/--host nécessite un argument"
                fi
                HOST="$2"
                shift 2
                ;;
            -p|--ports)
                if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                    error_exit "L'option -p/--ports nécessite un argument"
                fi
                PORTS="$2"
                SCAN_MODE="list"
                shift 2
                ;;
            -r|--range)
                if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                    error_exit "L'option -r/--range nécessite un argument"
                fi
                # Parse la plage (format: start-end)
                if [[ "$2" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                    PORT_START="${BASH_REMATCH[1]}"
                    PORT_END="${BASH_REMATCH[2]}"
                    SCAN_MODE="range"
                else
                    error_exit "Format de plage invalide. Utilisez: start-end (ex: 1-100)"
                fi
                shift 2
                ;;
            -t|--timeout)
                if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                    error_exit "L'option -t/--timeout nécessite un argument"
                fi
                TIMEOUT_DELAY="$2"
                shift 2
                ;;
            -o|--output)
                if [[ -z "$2" ]] || [[ "$2" == -* ]]; then
                    error_exit "L'option -o/--output nécessite un argument"
                fi
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -H|--help)
                show_help
                ;;
            -V|--version)
                show_version
                ;;
            -*)
                error_exit "Option inconnue: $1\nUtilisez -H pour afficher l'aide."
                ;;
            *)
                error_exit "Argument inattendu: $1"
                ;;
        esac
    done
}

#===============================================================================
# VALIDATION DES PARAMÈTRES
#===============================================================================

validate_parameters() {
    # Vérifie que l'hôte est spécifié
    if [[ -z "$HOST" ]]; then
        error_exit "L'hôte cible est requis. Utilisez -h <host>"
    fi
    
    # Valide le format de l'hôte
    if ! validate_host "$HOST"; then
        error_exit "Format d'hôte invalide: $HOST"
    fi
    
    # Vérifie qu'une méthode de scan est spécifiée
    if [[ -z "$PORTS" ]] && [[ -z "$PORT_START" ]]; then
        error_exit "Spécifiez des ports avec -p ou une plage avec -r"
    fi
    
    # Valide la plage si spécifiée
    if [[ "$SCAN_MODE" == "range" ]]; then
        if ! validate_port "$PORT_START"; then
            error_exit "Port de début invalide: $PORT_START (doit être entre 1 et 65535)"
        fi
        if ! validate_port "$PORT_END"; then
            error_exit "Port de fin invalide: $PORT_END (doit être entre 1 et 65535)"
        fi
        if [[ "$PORT_START" -gt "$PORT_END" ]]; then
            error_exit "Le port de début doit être inférieur au port de fin"
        fi
    fi
    
    # Vérifie le fichier de sortie si spécifié
    if [[ -n "$OUTPUT_FILE" ]]; then
        # Vérifie qu'on peut écrire dans le répertoire
        local output_dir
        output_dir=$(dirname "$OUTPUT_FILE")
        if [[ ! -d "$output_dir" ]]; then
            error_exit "Le répertoire de sortie n'existe pas: $output_dir"
        fi
        if [[ ! -w "$output_dir" ]]; then
            error_exit "Pas de permission d'écriture dans: $output_dir"
        fi
    fi
}

#===============================================================================
# POINT D'ENTRÉE PRINCIPAL
#===============================================================================

main() {
    # Affiche le banner
    echo ""
    echo -e "${CYAN}  ____            _     ____                                 ${NC}"
    echo -e "${CYAN} |  _ \\ ___  _ __| |_  / ___|  ___ __ _ _ __  _ __   ___ _ __ ${NC}"
    echo -e "${CYAN} | |_) / _ \\| '__| __| \\___ \\ / __/ _\` | '_ \\| '_ \\ / _ \\ '__|${NC}"
    echo -e "${CYAN} |  __/ (_) | |  | |_   ___) | (_| (_| | | | | | | |  __/ |   ${NC}"
    echo -e "${CYAN} |_|   \\___/|_|   \\__| |____/ \\___\\__,_|_| |_|_| |_|\\___|_|   ${NC}"
    echo -e "${YELLOW}                                              v${VERSION}${NC}"
    echo ""
    
    # Parse et valide les arguments
    parse_arguments "$@"
    validate_parameters
    
    # Vérifie l'accessibilité de l'hôte (optionnel, peut être lent)
    log_verbose "Démarrage du scan sur $HOST"
    
    # Lance le scan
    run_scan
    exit_code=$?
    
    # Message final selon le résultat
    case $exit_code in
        0)
            echo -e "${GREEN}[✓] Scan terminé avec succès - Des ports ouverts ont été trouvés${NC}"
            ;;
        2)
            echo -e "${YELLOW}[!] Scan terminé - Aucun port ouvert trouvé${NC}"
            ;;
    esac
    
    exit $exit_code
}

# Appelle la fonction principale avec tous les arguments
main "$@"
