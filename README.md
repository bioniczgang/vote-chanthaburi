# เว็บโหวตกันเถอะ (Netlify)

เว็บโหวตกิจกรรม + โหวตโรงเรียนจังหวัดจันทบุรี + เติมเพชร/ตรวจสลิป + ร้านค้าเพชร + ไลฟ์แชท

- หน้าเว็บ: `public/index.html` (ไฟล์เดียว)
- ระบบหลังบ้าน: `netlify/functions/api.mjs` เก็บข้อมูลใน Netlify Blobs (ไม่ต้องตั้งฐานข้อมูลเพิ่ม)
- รายชื่อโรงเรียนเริ่มต้น: `public/schools.json` (244 แห่ง จาก Wikipedia)

## ค่าที่ตั้งได้ใน Netlify → Site configuration → Environment variables
| ชื่อ | ใช้ทำอะไร | ค่าเริ่มต้น |
|---|---|---|
| `ADMIN_USERS` | username ที่เป็นแอดมิน (คั่นด้วย ,) | `test` |
| `ANTHROPIC_API_KEY` | เปิดระบบอ่านสลิปด้วย AI (ไม่ใส่ก็ใช้งานได้ ตรวจสลิปด้วยตาแทน) | - |
| `ANTHROPIC_MODEL` | รุ่น AI ที่ใช้อ่านสลิป | `claude-sonnet-5-5` |
| `SESSION_SECRET` | กุญแจเซ็นชื่อการล็อกอิน (ไม่ใส่ ระบบสร้างให้เอง) | - |

หลัง deploy ครั้งแรก ให้สมัคร username `test` ทันทีก่อนแชร์ลิงก์
