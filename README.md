# VulnerableLMS - Web Security Laboratory & OWASP Coraza WAF

Учебная веб-лаборатория по веб-безопасности и практическому исследованию **Web Application Firewall (WAF)** enterprise-уровня. Лаборатория выполнена в виде университетского веб-портала с журналом оценок, форумом курса, административным пультом деканата и досье студентов.

---

## 🛡️ Архитектура безопасности и WAF

В проекте развернут **полноценный отдельный WAF-сервер (Reverse Proxy)** с официальным набором правил **OWASP ModSecurity Core Rule Set (CRS v4.10.0)**. Защита не имитируется кодом Python, а работает на уровне сетевого прокси.

```
       [ Браузер студента / Burp Suite / curl ]
                          │
                          ▼  (Порт 5001 - Публичный вход)
     ┌──────────────────────────────────────────────────┐
     │      OWASP Coraza WAF (Caddy v2 Reverse Proxy)   │
     │      Процесс: coraza-waf.exe                     │
     │                                                  │
     │  1. Официальный OWASP CRS v4.10.0:              │
     │     - 25 официальных модулей (661 SecRule)       │
     │     - crs-setup.conf + rules/*.conf              │
     │     - SQLi, XSS, RCE, LFI, SSRF, Scanners        │
     │                                                  │
     │  2. University Virtual Patching (Бизнес-логика): │
     │     - IDOR, Burp Suite Tampering, Forced Browsing│
     │                                                  │
     │  3. Режимы: OFF / DETECT (IDS) / BLOCK (IPS)     │
     │     Paranoia Level: L1 / L2                      │
     └────────────────────────┬─────────────────────────┘
                              │ Запрос чист (или DETECT)
                              ▼ (Порт 5002 - Внутренний)
     ┌──────────────────────────────────────────────────┐
     │        VulnerableLMS Backend (Flask + SQLite)    │
     │        Процесс: python app.py                    │
     │        Фильтры кода: Low / Medium / High / Safe  │
     └──────────────────────────────────────────────────┘
```

---

## 🏛️ Официальный набор правил OWASP CRS (v4.10.0)

Правила загружены напрямую из официального репозитория OWASP ([github.com/coreruleset/coreruleset](https://github.com/coreruleset/coreruleset)) и расположены в каталоге `owasp-crs/`:

* `owasp-crs/crs-setup.conf` — официальный конфигурационный файл параметров CRS (пороги Anomaly Scoring, Paranoia Level, политики инспекции).
* `owasp-crs/rules/` — **25 официальных файлов правил ModSecurity SecLang (661 правило):**
  * `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (SQL Injection Protection — 53 правила, интеграция libinjection)
  * `REQUEST-941-APPLICATION-ATTACK-XSS.conf` (Cross-Site Scripting — 42 правила, фильтрация тегов, событий DOM)
  * `REQUEST-932-APPLICATION-ATTACK-RCE.conf` (Remote Command Execution — 48 правил, шелл-бинарники, пайпы)
  * `REQUEST-930-APPLICATION-ATTACK-LFI.conf` (Local File Inclusion / Path Traversal — 21 правило)
  * `REQUEST-931-APPLICATION-ATTACK-RFI.conf` (Remote File Inclusion)
  * `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf` (SSRF, инъекции в NodeJS/серверные среды)
  * `REQUEST-913-SCANNER-DETECTION.conf` (Детектирование сканеров: sqlmap, nikto, acunetix, gobuster)
  * `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` (Контроль спецификаций HTTP RFC)
  * `REQUEST-944-APPLICATION-ATTACK-JAVA.conf` (Десериализация Java, Log4Shell / JNDI)
  * `REQUEST-949-BLOCKING-EVALUATION.conf` (Итоговая оценка Anomaly Score и блокировка)
  * И словари сигнатур `.data` (scanners-user-agents, unix-shell, windows-powershell, restricted-files).

Все правила можно просмотреть как в директории `owasp-crs/rules/`, так и прямо в веб-интерфейсе через консоль WAF по адресу: **http://127.0.0.1:5001/waf-dashboard**.

---

## 🎯 Двухуровневая модель защиты (2-Tier Defense)

1. **Базовый уровень (Generic Web Attacks):** Официальный OWASP Core Rule Set пресекает классические векторы атак (SQLi, XSS, RCE, LFI, SSRF).
2. **Уровень виртуального патчинга (Business Logic Virtual Patching):** Специализированные SecRules защищают уникальную университетскую логику (подмену ролей `is_admin` и токенов сессий в Burp Suite `/vault`, обращение к досье декана по IDOR `/idor`, скрытые админки `/portal/admin-console`).

---

## 🚀 Быстрый запуск

### 1. Установка зависимостей Python
```bash
pip install -r requirements.txt
```

### 2. Запуск лабораторной работы
```bash
python app.py
```

При запуске автоматически:
1. Проверяется наличие бинарного файла `coraza-waf.exe` (при отсутствии скачивается официальный бинарник Caddy v2 с Coraza).
2. Проверяется наличие официального каталога `owasp-crs/`.
3. Генерируются конфигурационные файлы `coraza_rules.conf` и `Caddyfile`.
4. Запускается отдельный фоновый процесс **OWASP Coraza WAF на порту 5001**.
5. Запускается бэкенд Flask на порту 5002.

### 3. Открытие в браузере
* Публичный веб-портал (через WAF): **http://127.0.0.1:5001**
* Панель управления WAF и аудит-лог: **http://127.0.0.1:5001/waf-dashboard**
* Автоматический сканер уязвимостей: **http://127.0.0.1:5001/scanner**

---

## 👨‍🏫 Как продемонстрировать WAF преподавателю

1. **Доказательство отдельного процесса WAF в ОС:**
   В PowerShell:
   ```powershell
   Get-Process coraza-waf
   netstat -ano | findstr :5001
   netstat -ano | findstr :5002
   ```
   Преподаватель увидит системный процесс `coraza-waf.exe`, слушающий порт `5001` (Reverse Proxy), и процесс Python на порту `5002`.

2. **Демонстрация официальных файлов OWASP CRS:**
   * Откройте папку `owasp-crs/rules/` в VS Code или перейдите в веб-интерфейсе на `/waf-dashboard`.
   * Покажите файл `owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (официальные комментарии OWASP, правила `id:942100`, проверка через libinjection).

3. **Сравнение прямого доступа и прокси WAF:**
   * Включите режим `WAF: BLOCK` в верхнем меню.
   * Отправьте SQL-инъекцию через WAF: `http://127.0.0.1:5001/sqli?query=' OR 1=1 --` — WAF перехватит запрос и выдаст страницу `403 Forbidden (Blocked by OWASP Coraza WAF)`.
   * Отправьте тот же запрос напрямую бэкенду в обход WAF: `http://127.0.0.1:5002/sqli?query=' OR 1=1 --` — база вернет оценки студентов (атака успешна). Это наглядно доказывает, что блокировку выполняет именно Reverse Proxy WAF.

4. **Просмотр промышленного JSON аудит-лога:**
   Откройте файл `coraza_audit.log` или страницу `/waf-dashboard`. Каждое срабатывание содержит `id` официального правила OWASP CRS (например, `id: 942100`), имя файла (`REQUEST-942-APPLICATION-ATTACK-SQLI.conf`), Transaction ID и детали атаки.
