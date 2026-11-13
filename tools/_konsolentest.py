"""Fährt den Assistenten der Einrichtung in einer echten Windows-Konsole. Hilfsprogramm des Selbsttests.

Unter Linux und macOS prüft der Selbsttest den Assistenten in einem Pseudo-Terminal. Das gibt es unter Windows
nicht. Dort startet er stattdessen dieses Programm in einer eigenen, unsichtbaren Konsole. Es

    1. startet darin die Einrichtung mit --vorschau (sie verändert also nichts),
    2. liest den Bildschirm der Konsole so, wie ein Mensch ihn sähe,
    3. legt Tastendrücke in den Eingabepuffer der Konsole: Pfeiltasten, Enter, einen Schlüssel,
    4. schreibt nach dem Ende auf, was auf dem Bildschirm stand.

So ist geprüft, was sich nur an einer echten Konsole zeigt: dass die Pfeiltasten ankommen, dass die
Steuerzeichen für Farbe und Cursor wirken statt als Zeichensalat zu erscheinen, und dass ein eingegebener
Schlüssel nicht auf dem Bildschirm steht.

    python tools\\_konsolentest.py <Projektordner> <Ergebnisdatei.json>

Aufzurufen mit einer eigenen Konsole (CREATE_NEW_CONSOLE). Nur Standardbibliothek.
"""
from __future__ import annotations

import ctypes
import json
import re
import subprocess
import sys
import time
from ctypes import wintypes as wt
from pathlib import Path

GEHEIM = "KONSOLE-GEHEIM-0123456789abcdef"
TEIL = 9                # so viele Zeichen werden zuerst getippt, der Rest folgt in einem Stück


class COORD(ctypes.Structure):
    _fields_ = [("X", wt.SHORT), ("Y", wt.SHORT)]


class SMALL_RECT(ctypes.Structure):
    _fields_ = [("Left", wt.SHORT), ("Top", wt.SHORT), ("Right", wt.SHORT), ("Bottom", wt.SHORT)]


class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
    _fields_ = [("dwSize", COORD), ("dwCursorPosition", COORD), ("wAttributes", wt.WORD), ("srWindow", SMALL_RECT),
                ("dwMaximumWindowSize", COORD)]


class KEY_EVENT_RECORD(ctypes.Structure):
    _fields_ = [("bKeyDown", wt.BOOL), ("wRepeatCount", wt.WORD), ("wVirtualKeyCode", wt.WORD), ("wVirtualScanCode", wt.WORD),
                ("uChar", wt.WCHAR), ("dwControlKeyState", wt.DWORD)]


class EREIGNIS(ctypes.Union):
    _fields_ = [("KeyEvent", KEY_EVENT_RECORD), ("fuellung", ctypes.c_byte * 16)]


class INPUT_RECORD(ctypes.Structure):
    _fields_ = [("EventType", wt.WORD), ("Event", EREIGNIS)]


# Taste -> (virtueller Tastencode, Scancode, Zeichen, Zustand). 0x0100 heisst: Taste des erweiterten Blocks.
TASTEN = {"hoch": (0x26, 0x48, "\0", 0x0100), "runter": (0x28, 0x50, "\0", 0x0100), "enter": (0x0D, 0x1C, "\r", 0)}


def main() -> int:
    projekt, ziel = Path(sys.argv[1]), Path(sys.argv[2])
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.GetStdHandle.restype = wt.HANDLE
    k32.ReadConsoleOutputCharacterW.argtypes = [wt.HANDLE, wt.LPWSTR, wt.DWORD, COORD, ctypes.POINTER(wt.DWORD)]
    k32.WriteConsoleInputW.argtypes = [wt.HANDLE, ctypes.POINTER(INPUT_RECORD), wt.DWORD, ctypes.POINTER(wt.DWORD)]
    k32.GetConsoleScreenBufferInfo.argtypes = [wt.HANDLE, ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO)]
    eingabe, ausgabe = k32.GetStdHandle(-10), k32.GetStdHandle(-11)
    ergebnis: dict = {"schritte": [], "bloecke": [], "geheim_gesehen": False, "fehler": "", "code": None, "bildschirm": []}

    def bildschirm() -> list[str]:
        info = CONSOLE_SCREEN_BUFFER_INFO()
        if not k32.GetConsoleScreenBufferInfo(ausgabe, ctypes.byref(info)):
            raise OSError(f"GetConsoleScreenBufferInfo: Fehler {ctypes.get_last_error()}")
        ergebnis["fenster"] = [info.srWindow.Right - info.srWindow.Left + 1, info.srWindow.Bottom - info.srWindow.Top + 1]
        puffer, gelesen, zeilen = ctypes.create_unicode_buffer(info.dwSize.X + 1), wt.DWORD(), []
        for y in range(min(info.dwCursorPosition.Y + 2, info.dwSize.Y)):
            k32.ReadConsoleOutputCharacterW(ausgabe, puffer, info.dwSize.X, COORD(0, y), ctypes.byref(gelesen))
            zeilen.append(puffer[:gelesen.value].rstrip())
        return zeilen

    def druecken(*tasten: str) -> None:
        ereignisse = []
        for taste in tasten:
            code, scan, zeichen, zustand = TASTEN.get(taste, (0, 0, taste, 0))
            for unten in (1, 0):
                e = INPUT_RECORD()
                e.EventType = 1         # KEY_EVENT
                e.Event.KeyEvent = KEY_EVENT_RECORD(unten, 1, code, scan, zeichen, zustand)
                ereignisse.append(e)
        feld, geschrieben = (INPUT_RECORD * len(ereignisse))(*ereignisse), wt.DWORD()
        if not k32.WriteConsoleInputW(eingabe, feld, len(ereignisse), ctypes.byref(geschrieben)) or geschrieben.value != len(ereignisse):
            raise OSError(f"WriteConsoleInputW: Fehler {ctypes.get_last_error()}")

    def frage(zeilen: list[str]) -> tuple[str, str, str] | None:
        """Die Frage, die gerade auf dem Bildschirm steht: (Titel, Zeile unter dem Zeiger, ganzer Block)."""
        koepfe = [nr for nr, z in enumerate(zeilen) if re.match(r"^  \? \S", z)]
        if not koepfe:
            return None
        block = zeilen[koepfe[-1]:]
        if not any("Esc " in z for z in block):
            return None
        titel = re.split(r"\s{2,}", block[0][4:])[0].strip()
        zeiger = next((z for z in block if re.match(r"^    [>›] ", z)), "")
        wo = re.split(r"\s{2,}", re.sub(r"^    [>›] (?:\(\*\) |\( \) |[●○] |\[.\] )?", "", zeiger))[0].strip()
        return titel, wo, "\n".join(block)

    try:
        prozess = subprocess.Popen([sys.executable, str(projekt / "tools" / "einrichten.py"), "--vorschau"], cwd=str(projekt))
        zuletzt, davor, eingegeben, schluss = None, None, 0, time.time() + 200
        while prozess.poll() is None and time.time() < schluss:
            time.sleep(0.25)
            zeilen = bildschirm()
            if any(GEHEIM[:TEIL] in z or GEHEIM[TEIL:] in z for z in zeilen):
                ergebnis["geheim_gesehen"] = True
            stand = frage(zeilen)
            ruhig, davor = stand is not None and stand == davor, stand
            if not ruhig or stand == zuletzt:       # erst handeln, wenn die Frage ruhig dasteht und neu ist
                continue
            titel, wo, block = stand
            ergebnis["schritte"].append([titel, wo])
            ergebnis["bloecke"].append(block)
            if titel == "Shodan" and not eingegeben:
                druecken(*GEHEIM[:TEIL])
                eingegeben = 1
            elif titel == "Shodan":
                if f"{TEIL} Zeichen" not in block:
                    ergebnis["fehler"] = "die Eingabe zeigt nicht an, wie viele Zeichen angekommen sind"
                druecken(*GEHEIM[TEIL:], "enter")
                eingegeben = 2
            elif titel == "Schlüssel" and not eingegeben:
                druecken("enter" if wo == "Shodan" else "hoch")
            elif titel == "Schlüssel":
                druecken("enter" if wo == "Weiter" else "hoch")
            else:
                druecken("enter")                   # jede andere Frage: die Vorgabe
            zuletzt = stand
        if prozess.poll() is None:
            prozess.kill()
            ergebnis["fehler"] = ergebnis["fehler"] or "der Assistent ist nicht zu Ende gekommen"
        ergebnis["code"] = prozess.wait(30)
        ergebnis["bildschirm"] = bildschirm()
    except Exception as e:                          # alles muss in der Ergebnisdatei landen: Diese Konsole sieht niemand
        ergebnis["fehler"] = f"{type(e).__name__}: {e}"
    ziel.write_text(json.dumps(ergebnis, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
