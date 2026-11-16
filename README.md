# PCAP Dashboard – V1

רשתות תקשורת · מטלה 1 · חלק ג'

כלי ב-Python שמקבל קובץ PCAP / PCAPNG, מחלץ ממנו בעצמו את המידע (חבילות, TCP Streams, טרנזקציות HTTP),
מציג אותו ב-Dashboard ומאפשר לשאול עליו שאלות בשפה חופשית בעזרת Gemini. כל תשובה של ה-AI מגיעה עם evidence
(frames ו-timestamps), והמערכת **בודקת אוטומטית** את ה-evidence מול החבילות האמיתיות.

## התקנה

דרוש Python 3.10 ומעלה.

```bash
git clone https://github.com/bnayaamitay/pcap-dashboard.git
cd pcap-dashboard
python -m venv .venv
.venv\Scripts\activate          # Windows   (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
```

### מפתח API ל-Gemini (חינמי)
1. נכנסים ל-https://aistudio.google.com/apikey ויוצרים מפתח.
2. מעתיקים את `.env.example` לקובץ חדש בשם `.env` ומדביקים בו את המפתח:
   ```
   GEMINI_API_KEY=המפתח-שלכם
   ```
   הקובץ `.env` נמצא ב-`.gitignore` ולכן לא עולה ל-GitHub. אפשר גם להדביק את המפתח ישירות בסרגל הצד של האפליקציה.

## הרצה

```bash
streamlit run app.py
```
הדפדפן נפתח בכתובת http://localhost:8501. בסרגל הצד בוחרים הקלטה מתיקיית `captures/` או מעלים קובץ.

בדיקות אוטומטיות (משוות לערכים שמצאנו ידנית ב-Wireshark):
```bash
python -m pytest -v
```

## מבנה הפרויקט

| קובץ | תפקיד |
|---|---|
| `pcap_analyzer.py` | קריאת ההקלטה, TCP reassembly, פענוח HTTP, התאמת בקשה↔תגובה, חילוץ SNI מ-TLS |
| `ai_assistant.py` | בניית ה-context ל-AI, הפרומפט, קריאה ל-Gemini ואימות ה-evidence |
| `charts.py` | הגרפים (Plotly) |
| `app.py` | ממשק ה-Dashboard (Streamlit) |
| `tests/test_analyzer.py` | בדיקות מול תוצאות החלק הידני |
| `captures/` | קובצי ההקלטה ששימשו אותנו |

## מה ה-Dashboard מציג

| לשונית | תוכן | סעיפים במטלה |
|---|---|---|
| כותרת | מספר חבילות, זמן התחלה/סיום, משך, גודל | 24 |
| Overview | נפח תעבורה לאורך זמן, התפלגות פרוטוקולים, כתובות קצה עיקריות ושיחות | 25, 26 |
| Packets | רשימת חבילות עם סינון לפי פרוטוקול / IP / פורט | — |
| HTTP Transactions | כל בקשה עם התגובה שלה: Method, Host, URI, כתובות, פורטים, Status, זמן תגובה, frames. לחיצה על שורה מציגה headers, פרמטרים ומספר מקטעי TCP | 27–29 |
| TCP Streams | כל חיבור TCP; בחירת stream מציגה את כל החבילות שלו ותיאור (handshake / FIN / RST) | 31 |
| Ask AI | שאלה חופשית, תשובה, רמת ביטחון ו-evidence מאומת | 30–34 |
| Exposure Report | מה גלוי לצותת: מידע שנשלח ב-HTTP גלוי לעומת מה שרואים גם ב-HTTPS (IP, גדלים, SNI) | יצירתיות |

## איך עובד חלק ה-AI

1. **ה-AI לא מקבל את קובץ ה-PCAP.** הקוד שלנו מחלץ את הנתונים ושולח רק JSON מסודר: סיכום ההקלטה, טבלת טרנזקציות, חיבורי TLS, וה-stream הנבחר. ה-stream שמצורף לשאלה נקבע לפי מספר שכתוב בשאלה ("stream 23") או לפי השורה שנבחרה בלשונית TCP Streams.
2. **עובדות מחושבות מראש** (`precomputed_facts`): הבקשה הכי איטית, ספירת status codes, בקשות לכל host ועוד מחושבים ב-Python. המודל לא צריך לבצע חישובים על טבלאות ארוכות.
3. **פלט מובנה**: המודל מחזיר JSON עם `answer`, `evidence`, `confidence` ו-`caveats`.
4. **אימות evidence**: לכל frame שהמודל מצטט בודקים שהוא קיים ושה-timestamp תואם. מוצגים ✅ / ⚠️ / ❌, ואם יש evidence שגוי רמת הביטחון יורדת ל-low.
5. **מודל**: `gemini-3.1-flash-lite`, המודל הקל ביותר שזמין לחשבון, כדי לחסוך בטוקנים (מוגדר ב-`DEFAULT_MODEL` בקובץ `ai_assistant.py`). המודל `gemini-2.5-flash-lite` כבר לא זמין למשתמשים חדשים.
6. **פרטיות**: כתובות אימייל ומספרי טלפון מוסתרים לפני השליחה (ניתן לכבות בסרגל הצד).

## הערות טכניות
- מספרי ה-frame זהים לעמודה No. ב-Wireshark (מתחילים ב-1).
- הודעת HTTP שהתפצלה לכמה מקטעי TCP מדווחת ב-frame שהשלים אותה, כמו ב-Wireshark. מקטעים שהגיעו שלא לפי הסדר ו-retransmissions מטופלים.
- זמן תגובה = הזמן בין ה-frame של הבקשה ל-frame של התגובה (כמו `http.time` ב-Wireshark).
- התאמת בקשה לתגובה נעשית לפי הסדר באותו חיבור TCP (כך עובד HTTP/1.1).
