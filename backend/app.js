require('dotenv').config(); // 🌟 เรียกใช้ dotenv ไว้บนสุด
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { sequelize, User, Hotel, Room } = require('./models');

// นำเข้า Routes ต่างๆ
const authRoutes = require('./routes/authRoutes');
const hotelRoutes = require('./routes/hotelRoutes');
const bookingRoutes = require('./routes/bookingRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
app.use(cors());
app.use(express.json());

// ผูก Routes เข้ากับ API Paths หลัก
app.use('/api', authRoutes);               // สมัคร, ล็อกอิน
app.use('/api/hotels', hotelRoutes);       // ค้นหาโรงแรม
app.use('/api', bookingRoutes);            // จัดการการจองของลูกค้า
app.use('/api/admin', adminRoutes);        // จัดการหลังบ้าน (แอดมิน)

// ==========================================
// การเริ่มต้นฐานข้อมูลและเซิร์ฟเวอร์
// ==========================================
sequelize.sync({ force: true }).then(async () => {
    const adminPass = await bcrypt.hash('admin123', 10);
    // สร้างบัญชี Admin เริ่มต้น
    await User.create({ username: 'Admin System', email: 'admin@hotel.com', password_hash: adminPass, role: 'พนักงาน' });
    
    // 🌟 ชุดข้อมูลโรงแรม Dummy ที่เพิ่มที่อยู่และเบอร์โทร
    const hotels = [
        { 
            name: 'Bangkok City Hotel', loc: 'Bangkok', rate: 9.5, 
            addr: '123 ถนนสุขุมวิท เขตวัฒนา กรุงเทพฯ 10110', // เพิ่มที่อยู่
            tel: '02-123-4567', // เพิ่มเบอร์โทร
            desc: 'หรูหราใจกลางกรุง', img: 'https://images.unsplash.com/photo-1566073771259-6a8506099945?w=600' 
        },
        { 
            name: 'Phuket Sea Breeze', loc: 'Phuket', rate: 9.8, 
            addr: '45 หาดป่าตอง อำเภอกะทู้ ภูเก็ต 83150', 
            tel: '076-999-888',
            desc: 'วิวทะเลหลักล้าน', img: 'https://images.unsplash.com/photo-1520250497591-112f2f40a3f4?w=600' 
        },
        { 
            name: 'Chiang Mai Retreat', loc: 'Chiang Mai', rate: 9.2, 
            addr: '78 ถนนนิมมานเหมินท์ ซอย 5 เชียงใหม่ 50200', 
            tel: '053-111-222',
            desc: 'พักผ่อนท่ามกลางขุนเขา', img: 'https://images.unsplash.com/photo-1584132967334-10e028bd69f7?w=600' 
        },
        { 
            name: 'Hua Hin Sands', loc: 'Prachuap Khiri Khan', rate: 10.0, 
            addr: '99 ถนนเพชรเกษม หัวหิน ประจวบคีรีขันธ์ 77110', 
            tel: '032-555-444',
            desc: 'บ้านพักตากอากาศสุดส่วนตัว', img: 'https://images.unsplash.com/photo-1571896349842-33c89424de2d?w=600' 
        },
        { 
            name: 'Khao Yai Nature', loc: 'Nakhon Ratchasima', rate: 9.0, 
            addr: '10 หมู่ 1 ตำบลหมูสี อำเภอปากช่อง นครราชสีมา 30130', 
            tel: '044-777-666',
            desc: 'อากาศบริสุทธิ์ใกล้กรุง', img: 'https://images.unsplash.com/photo-1564501049412-61c2a3083791?w=600' 
        }
    ];

    for (const h of hotels) {
        // 🌟 อัปเดตคำสั่ง create ให้ดึงค่า addr และ tel มาใช้
        const createdHotel = await Hotel.create({ 
            hotel_name: h.name, 
            location: h.loc, 
            address: h.addr, // ส่งที่อยู่ลง DB
            contact_number: h.tel, // ส่งเบอร์โทรลง DB
            rating: h.rate, 
            description: h.desc, 
            image_url: h.img 
        });

        // เพิ่มห้องพักเริ่มต้น (คงเดิม)
        await Room.create({ hotel_id: createdHotel.hotel_id, room_name: '101', room_type: 'Standard', price_per_night: 1200, max_occupancy: 2 });
        await Room.create({ hotel_id: createdHotel.hotel_id, room_name: '201', room_type: 'Deluxe', price_per_night: 2500, max_occupancy: 2 });
    }



// ... โค้ดส่วนอื่น ๆ ของลูกพี่ ...

// 🌟 เปลี่ยนจาก 3000 เป็นค่าจาก .env ถ้าไม่มีให้ใช้ 3000 เป็นค่า Default
const PORT = process.env.PORT || 3000; 

app.listen(PORT, () => {
    console.log(`http://localhost:${PORT}`);
});
});