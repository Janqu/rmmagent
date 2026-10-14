# QDT Virtual Display

Minimaler UMDF/IDDCX-Treiber für die QDT-Fernwartung. Er stellt genau einen
virtuellen Bildschirm bereit, wenn ein Windows-Agent keinen nutzbaren Monitor
hat. Der Treiber enthält keinen Netzwerkcode und verarbeitet keine Eingaben.

Unterstützte Modi:

- 1920 × 1080 bei 60 Hz (bevorzugt)
- 1280 × 720 bei 60 Hz

Zielplattform ist Windows 10 ab Build 19041 und Windows 11 auf x64. Die
Hardware-ID lautet `Root\QDTVirtualDisplay`. Der Go-Agent installiert und
aktiviert das Gerät nur für eine Headless-Fernwartung und deaktiviert es nach
Sitzungsende wieder.

## Bauen

Benötigt werden Visual Studio 2022, Desktop C++, das aktuelle Windows SDK und
WDK. In einer Developer PowerShell:

```powershell
msbuild .\QdtVirtualDisplay.vcxproj /m /p:Configuration=Release /p:Platform=x64
```

Für Entwicklung darf ausschließlich auf einer Testmaschine mit aktivierter
Testsignierung gebaut werden. Für Releases müssen DLL, INF und CAT über das
Microsoft Hardware Dev Center signiert werden. Das signierte Paket wird nach
`build/qdt-virtual-display/package/` des Agent-Repositories kopiert; der
Inno-Installer nimmt es dann unter `drivers/qdt-virtual-display` auf.

Vor einer Freigabe sind mindestens Standby/Wakeup, Ab- und Anmeldung,
Windows-Update sowie Intel-, AMD-, NVIDIA- und VM-Grafikadapter zu prüfen.

## Herkunft

Die IDDCX-Grundstruktur basiert auf Microsofts `IddSampleDriver`. Dessen
MIT-Lizenz liegt als `LICENSE.microsoft.txt` bei. QDT-spezifisch sind die
Geräteidentität, der einzelne EDID-lose Monitor und die begrenzte Modusliste.
