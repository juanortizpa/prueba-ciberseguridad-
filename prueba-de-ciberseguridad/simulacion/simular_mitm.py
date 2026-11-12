#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simular_mitm.py - Simulacion en terminal de un ataque MITM en una red SDN.
=============================================================================
Pensada para maquinas con pocos recursos (8 GB de RAM) y SIN entorno grafico:
NO emula la red (nada de Mininet, OVS, Ryu, scapy ni root). SIMULA, paso a
paso y en la terminal, el flujo completo del ataque y de su mitigacion para
MOSTRARSELO a los estudiantes.

Reproduce el mismo escenario que el laboratorio real de este repositorio:

    Plano de control (SDN)        Controlador Ryu  (OpenFlow 1.3)
                                        |
    Plano de datos          h1 ---- [ OVS / br0 ] ---- h2
    10.0.0.0/24                          |
                                        h3  (atacante)

Fases (coinciden con docs/ del proyecto):
    1. Linea base ......... la red funciona; el controlador instala flujos.
    2. ARP Spoofing ....... h3 envenena las caches ARP de h1 y h2.
    3. Interceptacion ..... el trafico h1<->h2 pasa por h3 (MITM activo).
    4. Modificacion ....... h3 altera el mensaje al vuelo.
    5. Inyeccion SDN ...... (variante) h3 inyecta un flujo OpenFlow malicioso.
    6. Mitigacion ......... el controlador detecta el spoofing y bloquea a h3.

Uso:
    python3 simulacion/simular_mitm.py            # interactivo (Enter avanza)
    python3 simulacion/simular_mitm.py --auto     # avanza solo (para proyectar)
    python3 simulacion/simular_mitm.py --rapido   # pausas cortas
    python3 simulacion/simular_mitm.py --sin-color # sin colores ANSI
    python3 simulacion/simular_mitm.py --fase 3   # empezar en una fase

Solo requiere Python 3.6+. No necesita internet, ni sudo, ni paquetes extra.
"""

import argparse
import os
import sys
import time

# ---------------------------------------------------------------------------
#  Datos del laboratorio (mismos valores que lab.sh / docs del proyecto)
# ---------------------------------------------------------------------------
HOSTS = {
    "h1": {"ip": "10.0.0.11", "mac": "02:00:00:00:00:11", "rol": "victima A"},
    "h2": {"ip": "10.0.0.12", "mac": "02:00:00:00:00:12", "rol": "victima B"},
    "h3": {"ip": "10.0.0.66", "mac": "02:00:00:00:00:66", "rol": "ATACANTE"},
}
MAC = {k: v["mac"] for k, v in HOSTS.items()}
IP = {k: v["ip"] for k, v in HOSTS.items()}


# ---------------------------------------------------------------------------
#  Colores ANSI (se desactivan solos si no hay terminal o con --sin-color)
# ---------------------------------------------------------------------------
class C:
    enabled = True

    RESET = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"; GREY = "\033[90m"
    WHITE = "\033[97m"

    @classmethod
    def off(cls):
        cls.enabled = False
        for name in ("RESET", "BOLD", "DIM", "RED", "GREEN", "YELLOW",
                     "BLUE", "MAGENTA", "CYAN", "GREY", "WHITE"):
            setattr(cls, name, "")


def c(text, color):
    return "%s%s%s" % (color, text, C.RESET) if C.enabled else text


# Paleta por rol (para que los estudiantes asocien color <-> actor)
def host_color(name):
    return {"h1": C.BLUE, "h2": C.BLUE, "h3": C.RED}.get(name, C.WHITE)


# ---------------------------------------------------------------------------
#  Temporizacion y pausas
# ---------------------------------------------------------------------------
class Flow:
    """Controla el ritmo: interactivo (Enter) o automatico (temporizado)."""
    def __init__(self, auto=False, rapido=False, sin_pausa=False):
        self.auto = auto
        self.sin_pausa = sin_pausa
        self.k = 0.35 if rapido else 1.0

    def nap(self, seconds):
        if self.sin_pausa:
            return
        time.sleep(seconds * self.k)

    def beat(self, seconds=0.6):
        """Pequena pausa dramatica entre lineas."""
        self.nap(seconds)

    def wait(self, msg="Pulsa Enter para continuar"):
        """Entre fases: espera Enter, o una pausa larga en modo --auto."""
        if self.sin_pausa:
            return
        if self.auto:
            time.sleep(2.6 * self.k)
            return
        try:
            input(c("\n   %s  %s" % ("⏎", msg), C.GREY))
        except (EOFError, KeyboardInterrupt):
            print()
            sys.exit(0)


# ---------------------------------------------------------------------------
#  Utilidades de impresion
# ---------------------------------------------------------------------------
WIDTH = 72

def rule(char="─"):
    print(c(char * WIDTH, C.GREY))

def mac_s(m):
    """Muestra la MAC abreviada: 02:00:00:00:00:66 -> ..:66"""
    return ".." + m[-3:]

def banner():
    line = "=" * WIDTH
    print(c(line, C.CYAN))
    title = "SIMULACION  ::  Ataque MITM en una red SDN  (ARP Spoofing)"
    print(c(title.center(WIDTH), C.BOLD + C.CYAN))
    print(c("Especializacion en Ciberseguridad   -  laboratorio aislado".center(WIDTH), C.CYAN))
    print(c(line, C.CYAN))
    print(c("  Entorno SIMULADO (no emulado): corre en terminal, sin VMs, sin root.".center(WIDTH), C.DIM))
    print()


def fase_header(num, total, titulo):
    rule("═")
    etiqueta = " FASE %d/%d " % (num, total)
    print(c(etiqueta, C.BOLD + C.YELLOW) + c(" " + titulo, C.BOLD + C.WHITE))
    rule("═")


def paso(texto):
    print(c("  ‣ ", C.CYAN) + texto)


def nota(texto):
    print(c("  ⓘ  ", C.MAGENTA) + c(texto, C.MAGENTA))


# ---------------------------------------------------------------------------
#  Topologia ASCII (se adapta: normal / MITM / bloqueado)
# ---------------------------------------------------------------------------
def topologia(estado="normal"):
    """
    estado: 'normal' | 'mitm' | 'bloqueado'
    Dibuja la red en ASCII mostrando por donde viaja el trafico.
    """
    ryu = c("Controlador Ryu", C.CYAN)
    ovs = c("[ OVS br0 ]", C.MAGENTA)
    h1 = c("h1", C.BLUE); h2 = c("h2", C.BLUE); h3 = c("h3", C.RED)

    if estado == "mitm":
        via = c("tráfico desviado por h3", C.RED)
        flecha1 = c("══▶", C.RED)
        flecha2 = c("══▶", C.RED)
    elif estado == "bloqueado":
        via = c("h3 BLOQUEADO — h1↔h2 directo", C.GREEN)
        flecha1 = c("──▶", C.GREEN)
        flecha2 = c("──▶", C.GREEN)
    else:
        via = c("h1 ↔ h2 directo", C.GREEN)
        flecha1 = c("──▶", C.GREEN)
        flecha2 = c("──▶", C.GREEN)

    print()
    print("          " + ryu + c("   (SDN · OpenFlow 1.3 · :6653)", C.DIM))
    print("                 " + c("│", C.CYAN) + c("  plano de control", C.DIM))
    print("    " + h1 + c(" ", C.RESET) + flecha1 + "  " + ovs + "  " + flecha2 + " " + h2
          + "     " + c("(" + via + ")", C.DIM))
    print("   " + c(IP["h1"], C.DIM) + "            " + c("│", C.MAGENTA)
          + "            " + c(IP["h2"], C.DIM))
    if estado == "mitm":
        print("                  " + c("▼", C.RED))
        print("                 " + h3 + c("  ☠  intercepta y reenvia", C.RED))
    elif estado == "bloqueado":
        print("                  " + c("╳", C.GREEN) + c(" (flujo DROP)", C.GREEN))
        print("                 " + h3 + c("  ✖ descartado en el switch", C.GREEN))
    else:
        print("                  " + c("│", C.GREY))
        print("                 " + h3 + c("  (inactivo)", C.DIM))
    print("                " + c(IP["h3"], C.DIM))
    print()


# ---------------------------------------------------------------------------
#  Paneles: caches ARP, tabla de flujos, consola del controlador
# ---------------------------------------------------------------------------
def panel_arp(caches):
    """caches: {host: [(ip, mac, estado)]}  estado: 'ok'|'spoof'|'real'"""
    print(c("  Caches ARP de los equipos (\"quien tiene\" cada IP):", C.BOLD))
    for h in ("h1", "h2", "h3"):
        filas = caches.get(h, [])
        etiqueta = "%s %s %s" % (
            c(h, host_color(h) + C.BOLD),
            c(IP[h], C.DIM),
            c("(" + HOSTS[h]["rol"] + ")", C.DIM),
        )
        print("    " + etiqueta)
        if not filas:
            print(c("        (sin entradas relevantes)", C.DIM))
            continue
        for ip_, mac_, estado in filas:
            if estado == "spoof":
                destino = c(mac_s(mac_) + "  ⚠ MAC del atacante", C.RED + C.BOLD)
            elif estado == "ok":
                destino = c(mac_s(mac_) + "  ✓", C.GREEN)
            else:
                destino = c(mac_s(mac_), C.WHITE)
            print("        %-11s → %s" % (c(ip_, C.WHITE), destino))
    print()


def panel_flujos(flujos):
    print(c("  Tabla de flujos del OVS (ovs-ofctl dump-flows br0):", C.BOLD))
    for pri, texto, tipo, nuevo in flujos:
        col = {"miss": C.GREY, "ok": C.BLUE, "evil": C.RED, "drop": C.GREEN}.get(tipo, C.WHITE)
        marca = c("  ◀ nuevo", C.YELLOW) if nuevo else ""
        print("    " + c("priority=%-3d" % pri, C.DIM) + " " + c(texto, col) + marca)
    print()


def consola_ryu(app, lineas):
    print(c("  Consola del controlador Ryu  ", C.BOLD) + c("[ %s ]" % app, C.CYAN))
    for t, tipo, texto in lineas:
        col = {"info": C.GREY, "arp": C.BLUE, "detect": C.YELLOW,
               "block": C.GREEN + C.BOLD}.get(tipo, C.WHITE)
        print("    " + c("[%5ss]" % t, C.DIM) + " " + c(texto, col))
    print()


def paquete(origen, destino, etiqueta, contenido=None, color=C.WHITE, flow=None):
    """Imprime un 'paquete' simulado viajando por la red."""
    linea = "    %s %s %s %s %s" % (
        c(origen, host_color(origen) + C.BOLD),
        c("──[OVS]──▶", color),
        c(destino, host_color(destino) + C.BOLD),
        c("⟪" + etiqueta + "⟫", color + C.BOLD),
        c('"%s"' % contenido, C.WHITE) if contenido else "",
    )
    print(linea)
    if flow:
        flow.beat(0.5)


# ---------------------------------------------------------------------------
#  Estados ARP por fase
# ---------------------------------------------------------------------------
def arp_normal():
    return {
        "h1": [(IP["h2"], MAC["h2"], "ok")],
        "h2": [(IP["h1"], MAC["h1"], "ok")],
        "h3": [],
    }

def arp_envenenado():
    return {
        "h1": [(IP["h2"], MAC["h3"], "spoof")],
        "h2": [(IP["h1"], MAC["h3"], "spoof")],
        "h3": [(IP["h1"], MAC["h1"], "real"), (IP["h2"], MAC["h2"], "real")],
    }


def flujos_base():
    return [
        (0, "actions=CONTROLLER:65535", "miss", False),
        (1, "in_port=1,eth_dst=..:12 actions=output:2", "ok", False),
        (1, "in_port=2,eth_dst=..:11 actions=output:1", "ok", False),
    ]

def flujos_evil():
    return flujos_base() + [
        (100, "cookie=0x6d69746d,ip,nw_src=10.0.0.11 actions=output:3,output:2", "evil", True),
    ]

def flujos_drop():
    return flujos_base() + [
        (101, "arp,eth_src=..:66 actions=drop", "drop", True),
        (100, "eth_src=..:66 actions=drop", "drop", True),
    ]


# ---------------------------------------------------------------------------
#  FASES
# ---------------------------------------------------------------------------
def fase1(flow):
    fase_header(1, 6, "Linea base: la red funciona con normalidad")
    topologia("normal")
    paso("h1 quiere enviarle un mensaje a h2 (10.0.0.12).")
    flow.beat()
    paso("El switch OVS no conoce el camino: pregunta al controlador (packet-in).")
    flow.beat()
    paso("Ryu aprende las MAC, instala flujos y el paquete viaja directo.")
    flow.beat(0.8)
    print()
    paquete("h1", "h2", "MSG", "Hola h2, aqui h1", C.BLUE, flow)
    print()
    panel_arp(arp_normal())
    panel_flujos(flujos_base())
    consola_ryu("simple_switch_13", [
        ("00.0", "info", "switch conectado: dpid=1 (table-miss instalado)"),
        ("00.1", "info", "packet-in: aprende ..:11 en puerto 1"),
        ("00.2", "info", "packet-in: aprende ..:12 en puerto 2"),
        ("00.3", "info", "flujo h1<->h2 instalado  (trafico directo)"),
    ])
    nota("Cada equipo tiene en su cache la MAC VERDADERA del otro. Nadie en medio.")
    flow.wait()


def fase2(flow):
    fase_header(2, 6, "ARP Spoofing: el atacante envenena las caches")
    paso("h3 (atacante) no rompe nada: abusa de que ARP no verifica identidades.")
    flow.beat()
    paso("Envia respuestas ARP falsas (\"gratuitous ARP\") a las dos victimas:")
    flow.beat(0.8)
    print()
    print("    " + c("h3 ─▶ h1:", C.RED) + c('  "10.0.0.12 (h2) esta en MI MAC %s"' % mac_s(MAC["h3"]), C.RED))
    flow.beat(0.7)
    print("    " + c("h3 ─▶ h2:", C.RED) + c('  "10.0.0.11 (h1) esta en MI MAC %s"' % mac_s(MAC["h3"]), C.RED))
    flow.beat(0.8)
    print()
    paso("h1 y h2 creen el engano y actualizan su cache ARP:")
    print()
    panel_arp(arp_envenenado())
    consola_ryu("simple_switch_13", [
        ("12.0", "arp", "packet-in: ARP is-at 10.0.0.12 -> ..:66 (inundado)"),
        ("12.1", "arp", "packet-in: ARP is-at 10.0.0.11 -> ..:66 (inundado)"),
        ("12.2", "info", "simple_switch_13 solo conmuta: NO inspecciona ARP"),
    ])
    nota("El ultimo que 'responde' ARP gana. Ahora h1 y h2 apuntan a la MAC de h3.")
    flow.wait()


def fase3(flow):
    fase_header(3, 6, "Interceptacion: el trafico pasa por el atacante")
    topologia("mitm")
    paso("Ahora h1 le escribe a h2... pero su cache dice que h2 esta en la MAC de h3.")
    flow.beat(0.8)
    print()
    paquete("h1", "h3", "MSG", "h2, transfiere $100", C.RED, flow)
    print("        " + c("⤷ h3 lo recibe, lo LEE y lo reenvia (IP forwarding):", C.RED))
    flow.beat(0.7)
    paquete("h3", "h2", "MSG", "h2, transfiere $100", C.YELLOW, flow)
    print()
    paso("La conexion 'funciona': ni h1 ni h2 notan nada.")
    flow.beat()
    panel_arp(arp_envenenado())
    consola_ryu("simple_switch_13", [
        ("20.0", "info", "el switch entrega a la MAC ..:66 (h3)"),
        ("20.1", "arp", "h3: net.ipv4.ip_forward=1  (reenvia a h2)"),
        ("20.2", "info", "h3 captura: ICMP/TCP h1->h2  (modo sniff)"),
    ])
    nota("MITM activo: h3 ve el contenido en claro. Es silencioso porque todo sigue llegando.")
    flow.wait()


def fase4(flow):
    fase_header(4, 6, "Modificacion: el atacante altera el mensaje al vuelo")
    paso("h3 no solo mira: reescribe el contenido antes de reenviarlo (NFQUEUE).")
    flow.beat(0.8)
    print()
    paquete("h1", "h3", "MSG", "h2, transfiere $100", C.RED, flow)
    print("        " + c("⤷ h3 busca \"$100\" y lo cambia por \"$9000\":", C.RED + C.BOLD))
    flow.beat(0.7)
    paquete("h3", "h2", "MSG", "h2, transfiere $9000", C.RED + C.BOLD, flow)
    print()
    paso("h2 recibe el mensaje MODIFICADO como si viniera de h1.")
    flow.beat()
    consola_ryu("simple_switch_13", [
        ("30.0", "info", "NFQUEUE: paquete TCP interceptado"),
        ("30.1", "detect", "payload MODIFICADO: '$100' -> '$9000'"),
        ("30.2", "info", "reenviado a h2 (checksums recalculados)"),
    ])
    nota("Integridad rota: sin cifrado, el atacante cambia datos sin dejar rastro visible.")
    flow.wait()


def fase5(flow):
    fase_header(5, 6, "Variante SDN: inyectar un flujo OpenFlow malicioso")
    paso("En SDN hay un segundo vector: abusar del plano de control.")
    flow.beat()
    paso("Si la API REST de Ryu queda expuesta, h3 instala un flujo de alta prioridad")
    paso("que DUPLICA el trafico de h1 hacia el puerto del atacante (ademas del normal):")
    flow.beat(0.8)
    print()
    print("    " + c("POST http://192.168.100.10:8080/stats/flowentry/add", C.RED))
    flow.beat(0.6)
    print()
    panel_flujos(flujos_evil())
    consola_ryu("simple_switch_13 + ofctl_rest", [
        ("40.0", "arp", "REST POST /stats/flowentry/add"),
        ("40.1", "detect", "flujo cookie=0x6d69746d instalado (prio 100)"),
        ("40.2", "info", "copia del trafico de 10.0.0.11 -> puerto 3 (h3)"),
    ])
    nota("La cookie 0x6d69746d ('mitm') marca el flujo intruso para poder rastrearlo/borrarlo.")
    flow.wait()


def fase6(flow):
    fase_header(6, 6, "Mitigacion: el controlador detecta y bloquea a h3")
    paso("Cambiamos Ryu al modulo de defensa: mitigation/arp_monitor.py")
    flow.beat()
    paso("Mantiene una tabla ARP de CONFIANZA y vigila cambios de MAC:")
    flow.beat(0.8)
    print()
    print("    " + c("ARP de confianza:", C.CYAN) + "  10.0.0.11 → ..:11")
    flow.beat(0.6)
    print("    " + c("Observado ahora:", C.YELLOW) + "   10.0.0.11 → " + c("..:66", C.RED))
    flow.beat(0.5)
    print("    " + c("→ la IP cambio de MAC = ARP SPOOFING", C.YELLOW + C.BOLD))
    flow.beat(0.9)
    print()
    paso("El controlador instala un flujo DROP para la MAC del atacante:")
    print()
    panel_flujos(flujos_drop())
    topologia("bloqueado")
    paso("El trafico de h3 se descarta EN EL SWITCH y las caches se restauran:")
    print()
    paquete("h3", "h2", "MSG", "intento de ataque", C.GREEN, flow)
    print("        " + c("✖ descartado por el flujo DROP (eth_src=..:66)", C.GREEN + C.BOLD))
    flow.beat(0.7)
    paquete("h1", "h2", "MSG", "Hola h2, aqui h1", C.GREEN, flow)
    print("        " + c("✓ h1 ↔ h2 vuelve a ir directo", C.GREEN))
    print()
    panel_arp(arp_normal())
    consola_ryu("mitigation/arp_monitor", [
        ("50.0", "arp", "ARP de confianza: 10.0.0.11 -> ..:11"),
        ("50.1", "detect", "ARP_SPOOFING_DETECTED 10.0.0.11: ..:11 -> ..:66"),
        ("50.2", "block", "MAC_BLOCKED ..:66  (response_time=0.08s)"),
        ("50.3", "info", "flujo DROP instalado  ->  red restaurada"),
    ])
    nota("Defensa activa en SDN: el controlador tiene vision GLOBAL, detecta la anomalia")
    nota("y, en milisegundos, corta el trafico del atacante desde el switch.")
    flow.wait("Pulsa Enter para ver el resumen")


def resumen(flow):
    rule("═")
    print(c("  RESUMEN PARA LOS ESTUDIANTES".center(WIDTH), C.BOLD + C.CYAN))
    rule("═")
    puntos = [
        ("El ataque", "ARP Spoofing: ARP no autentica, el atacante se hace pasar "
                      "por el otro extremo y se pone 'en medio' (MITM)."),
        ("El dano", "Puede LEER (confidencialidad) y MODIFICAR (integridad) el "
                    "trafico sin que las victimas lo noten."),
        ("El rol de SDN", "El mismo plano de control que el atacante intenta abusar "
                          "es, bien usado, la mejor defensa."),
        ("La mitigacion", "El controlador vigila la relacion IP<->MAC; ante un cambio "
                          "sospechoso instala un flujo DROP y aisla al atacante."),
        ("La leccion", "Cifrado extremo a extremo + inspeccion en el controlador = "
                       "el MITM deja de ser invisible y deja de funcionar."),
    ]
    for titulo, texto in puntos:
        print("  " + c("▸ " + titulo + ": ", C.BOLD + C.YELLOW))
        for linea in _wrap(texto, WIDTH - 6):
            print("      " + linea)
        flow.beat(0.4)
    print()
    print(c("  Mapa con el laboratorio REAL (cuando haya mas RAM):", C.DIM))
    print(c("    Fase 1 -> controller/simple_switch_13.py  +  ovs/setup_ovs.sh", C.DIM))
    print(c("    Fase 2 -> attack/arp_spoof.py  attack/mitm_intercept.py  attack/flow_inject.py", C.DIM))
    print(c("    Fase 4 -> mitigation/arp_monitor.py", C.DIM))
    print()
    rule("═")
    print(c("  Fin de la simulacion.  Uso exclusivo educativo / laboratorio aislado.".center(WIDTH), C.CYAN))
    rule("═")


def _wrap(texto, ancho):
    palabras = texto.split()
    lineas, actual = [], ""
    for p in palabras:
        if len(actual) + len(p) + 1 > ancho:
            lineas.append(actual)
            actual = p
        else:
            actual = (actual + " " + p).strip()
    if actual:
        lineas.append(actual)
    return lineas


# ---------------------------------------------------------------------------
#  Main
# ---------------------------------------------------------------------------
FASES = [fase1, fase2, fase3, fase4, fase5, fase6]


def main():
    parser = argparse.ArgumentParser(
        description="Simulacion en terminal de un ataque MITM en SDN (educativa).")
    parser.add_argument("--auto", action="store_true",
                        help="Avanza solo, sin esperar Enter (ideal para proyectar).")
    parser.add_argument("--rapido", action="store_true",
                        help="Pausas mas cortas.")
    parser.add_argument("--sin-pausa", action="store_true",
                        help="Sin pausas: imprime todo de corrido.")
    parser.add_argument("--sin-color", action="store_true",
                        help="Desactiva los colores ANSI.")
    parser.add_argument("--fase", type=int, default=1, metavar="N",
                        help="Empezar en la fase N (1-6).")
    args = parser.parse_args()

    if args.sin_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        C.off()

    flow = Flow(auto=args.auto, rapido=args.rapido, sin_pausa=args.sin_pausa)

    inicio = max(1, min(args.fase, len(FASES)))

    try:
        banner()
        if not args.sin_pausa and not args.auto and inicio == 1:
            flow.wait("Pulsa Enter para empezar la simulacion")
        for i in range(inicio - 1, len(FASES)):
            print()
            FASES[i](flow)
        print()
        resumen(flow)
    except KeyboardInterrupt:
        print(c("\n\n  Simulacion interrumpida. Hasta luego.\n", C.GREY))
        sys.exit(0)


if __name__ == "__main__":
    main()
