# SCT Code Server

API dùng chung cho Admin và Game.

## API
- GET `/api/health`
- GET `/api/codes` (Admin)
- POST `/api/codes` (Admin)
- PATCH `/api/codes/:code` (Admin)
- DELETE `/api/codes/:code` (Admin)
- POST `/api/redeem` (người chơi)

## Chạy
1. Cài Node.js 18+
2. `npm install`
3. Đặt `ADMIN_PASSWORD` bằng biến môi trường.
4. `npm start`

## Quan trọng
Server phải chạy ở hosting có Node.js. GitHub Pages chỉ phục vụ HTML/CSS/JS tĩnh, không chạy `server.js`.
Nếu host không có persistent disk, dữ liệu `data/codes.json` có thể mất khi server restart/redeploy; dùng persistent disk hoặc database khi triển khai thật.
