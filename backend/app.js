const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Op } = require('sequelize');
const { sequelize, User, Hotel, Room, Booking } = require('./models');

const app = express();
app.use(cors());
app.use(express.json());

const SECRET = 'hotelease_secret_key';

// ==========================================
// 1. MIDDLEWARE (ส่วนการตรวจสอบสิทธิ์)
// ==========================================

// ตรวจสอบ JWT Token
const auth = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Unauthorized' });
    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Forbidden' });
        req.user = user; 
        next();
    });
};

// ตรวจสอบว่าเป็นพนักงาน (Admin) หรือไม่
const isAdmin = (req, res, next) => req.user.role === 'พนักงาน' ? next() : res.status(403).send('Denied');

// ==========================================
// 2. AUTHENTICATION API (ระบบสมาชิก)
// ==========================================

// สมัครสมาชิก
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, contact_number, address } = req.body;
        const password_hash = await bcrypt.hash(password, 10);
        await User.create({ username, email, password_hash, contact_number, address, role: 'ลูกค้า' });
        res.json({ message: 'Success' });
    } catch (e) { res.status(400).json({ error: 'Email exists' }); }
});

// เข้าสู่ระบบ
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });
    if (user && await bcrypt.compare(password, user.password_hash)) {
        const token = jwt.sign({ user_id: user.user_id, role: user.role, username: user.username }, SECRET);
        res.json({ token, role: user.role, username: user.username });
    } else res.status(401).json({ message: 'Invalid credentials' });
});

// ==========================================
// 3. HOTEL & ROOM API (ระบบค้นหาและข้อมูลโรงแรม)
// ==========================================

// ฟังก์ชันค้นหาห้องที่ว่างเฉพาะ ในช่วงเวลา กับ เว้น Peding Confirmed
const getOverlappingRooms = async (check_in, check_out) => {
    const overlaps = await Booking.findAll({
        where: { 
            status: { [Op.in]: ['Pending', 'Confirmed'] }, 
            check_in_date: { [Op.lt]: check_out }, 
            check_out_date: { [Op.gt]: check_in } 
        }
    });
    return overlaps.map(b => b.room_id);
};

// ดึงรายการโรงแรมพร้อมกรองข้อมูล (Filter)
app.get('/api/hotels', async (req, res) => {
    const { location, room_type, max_price, check_in, check_out } = req.query;
    let hotelFilter = {}; 
    let roomFilter = { availability: true };

    if (location) hotelFilter.location = { [Op.like]: `%${location}%` };
    if (room_type) roomFilter.room_type = { [Op.like]: `%${room_type}%` }; //Op.like หาที่ระบุ
    if (max_price) roomFilter.price_per_night = { [Op.lte]: parseInt(max_price) }; ///Op.lte (Less Than or Equal) ไม่เกิน

    if (check_in && check_out) {
        const bookedIds = await getOverlappingRooms(check_in, check_out);
        if (bookedIds.length > 0) roomFilter.room_id = { [Op.notIn]: bookedIds }; ///Op.notIn ไม่อยู่ใน
    }
    const hotels = await Hotel.findAll({ where: hotelFilter, include: [{ model: Room, where: roomFilter, required: true }] });
    res.json(hotels);
});

// ดึงข้อมูลโรงแรมรายบุคคล
app.get('/api/hotels/:id', async (req, res) => {
    const { check_in, check_out } = req.query;
    let roomFilter = { availability: true };
    if (check_in && check_out) {
        const bookedIds = await getOverlappingRooms(check_in, check_out);
        if (bookedIds.length > 0) roomFilter.room_id = { [Op.notIn]: bookedIds };
    }
    const hotel = await Hotel.findByPk(req.params.id, { include: [{ model: Room, where: roomFilter, required: false }] });
    res.json(hotel);
});

// ==========================================
// 4. BOOKING API (ระบบการจองสำหรับลูกค้า)
// ==========================================

// ส่งคำขอจองห้องพัก
app.post('/api/book', auth, async (req, res) => {
    const { room_id, check_in_date, check_out_date, total_amount } = req.body;
    await Booking.create({ user_id: req.user.user_id, room_id, check_in_date, check_out_date, total_amount });
    res.json({ message: 'Booked' });
});

// ดูประวัติการจองของตัวเอง
app.get('/api/my-bookings', auth, async (req, res) => {
    const bookings = await Booking.findAll({ where: { user_id: req.user.user_id }, include: [{ model: Room, include: [Hotel] }] });
    res.json(bookings);
});

// ยกเลิกการจอง (เฉพาะสถานะ Pending)
app.put('/api/my-bookings/:id/cancel', auth, async (req, res) => {
    try {
        const booking = await Booking.findOne({ 
            where: { booking_id: req.params.id, user_id: req.user.user_id } 
        });

        if (!booking) return res.status(404).json({ error: 'ไม่พบข้อมูลการจองนี้' });
        if (booking.status !== 'Pending') {
            return res.status(400).json({ error: 'สามารถยกเลิกได้เฉพาะรายการที่รอดำเนินการเท่านั้น' });
        }

        await Booking.update({ status: 'Cancelled' }, { where: { booking_id: req.params.id } });
        res.json({ message: 'ยกเลิกการจองสำเร็จ' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ==========================================
// 5. ADMIN API (ระบบหลังบ้านสำหรับพนักงาน)
// ==========================================

// ดูรายการจองทั้งหมดในระบบ
app.get('/api/admin/bookings', auth, isAdmin, async (req, res) => {
    const bookings = await Booking.findAll({ include: [User, { model: Room, include: [Hotel] }], order: [['booking_date', 'DESC']] });
    res.json(bookings);
});

// อัปเดตสถานะการจอง (ดักห้ามแก้ถ้าเป็น Cancelled)
app.put('/api/admin/bookings/:id', auth, isAdmin, async (req, res) => {
    try {
        const booking = await Booking.findOne({ where: { booking_id: req.params.id } });
        if (!booking) return res.status(404).json({ error: 'ไม่พบข้อมูลการจอง' });

        if (booking.status === 'Cancelled') {
            return res.status(400).json({ error: 'ไม่สามารถเปลี่ยนสถานะของการจองที่ถูกยกเลิกไปแล้วได้' });
        }

        await Booking.update({ status: req.body.status }, { where: { booking_id: req.params.id } });
        res.json({ message: 'Updated' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ดึงข้อมูลทั้งหมดสำหรับจัดการโรงแรม/ห้องพัก
app.get('/api/admin/all-data', auth, isAdmin, async (req, res) => {
    const hotels = await Hotel.findAll({ include: [Room] });
    res.json(hotels);
});

// จัดการข้อมูลโรงแรม (Create, Update, Delete)
app.post('/api/admin/hotels', auth, isAdmin, async (req, res) => { await Hotel.create(req.body); res.json({ message: 'Added' }); });
app.put('/api/admin/hotels/:id', auth, isAdmin, async (req, res) => { await Hotel.update(req.body, { where: { hotel_id: req.params.id } }); res.json({ message: 'Updated' }); });
app.delete('/api/admin/hotels/:id', auth, isAdmin, async (req, res) => {
    const rooms = await Room.findAll({ where: { hotel_id: req.params.id } });
    const active = await Booking.count({ where: { room_id: { [Op.in]: rooms.map(r => r.room_id) }, status: { [Op.in]: ['Pending', 'Confirmed'] } } });
    if (active > 0) return res.status(400).json({ error: 'ลบไม่ได้ มีคนจองอยู่' });
    await Hotel.destroy({ where: { hotel_id: req.params.id } }); res.json({ message: 'Deleted' });
});

// จัดการข้อมูลห้องพัก (Create, Update, Delete)
app.post('/api/admin/rooms', auth, isAdmin, async (req, res) => { await Room.create(req.body); res.json({ message: 'Added' }); });
app.put('/api/admin/rooms/:id', auth, isAdmin, async (req, res) => { await Room.update(req.body, { where: { room_id: req.params.id } }); res.json({ message: 'Updated' }); });
app.delete('/api/admin/rooms/:id', auth, isAdmin, async (req, res) => {
    const active = await Booking.count({ where: { room_id: req.params.id, status: { [Op.in]: ['Pending', 'Confirmed'] } } });
    if (active > 0) return res.status(400).json({ error: 'ลบไม่ได้ มีคนจองอยู่' });
    await Room.destroy({ where: { room_id: req.params.id } }); res.json({ message: 'Deleted' });
});

// ==========================================
// 6. INITIALIZATION (การเริ่มต้นฐานข้อมูลและเซิร์ฟเวอร์)
// ==========================================

sequelize.sync({ force: true }).then(async () => {
    const adminPass = await bcrypt.hash('admin123', 10);
    // สร้างบัญชี Admin เริ่มต้น
    await User.create({ username: 'Admin System', email: 'admin@hotel.com', password_hash: adminPass, role: 'พนักงาน' });
    
    // ชุดข้อมูลโรงแรม Dummy
    const hotels = [
        { name: 'Bangkok City Hotel', loc: 'Bangkok', rate: 9.5, desc: 'หรูหราใจกลางกรุง', img: 'https://images.unsplash.com/photo-1566073771259-6a8506099945?w=600' },
        { name: 'Phuket Sea Breeze', loc: 'Phuket', rate: 9.8, desc: 'วิวทะเลหลักล้าน', img: 'https://images.unsplash.com/photo-1520250497591-112f2f40a3f4?w=600' },
        { name: 'Chiang Mai Retreat', loc: 'Chiang Mai', rate: 9.2, desc: 'พักผ่อนท่ามกลางขุนเขา', img: 'https://images.unsplash.com/photo-1584132967334-10e028bd69f7?w=600' },
        { name: 'Hua Hin Sands', loc: 'Prachuap Khiri Khan', rate: 10.0, desc: 'บ้านพักตากอากาศสุดส่วนตัว', img: 'https://images.unsplash.com/photo-1571896349842-33c89424de2d?w=600' },
        { name: 'Khao Yai Nature', loc: 'Nakhon Ratchasima', rate: 9.0, desc: 'อากาศบริสุทธิ์ใกล้กรุง', img: 'https://images.unsplash.com/photo-1564501049412-61c2a3083791?w=600' }
    ];

    for (const h of hotels) {
        const createdHotel = await Hotel.create({ 
            hotel_name: h.name, 
            location: h.loc, 
            rating: h.rate, 
            description: h.desc, 
            image_url: h.img 
        });
        // เพิ่มห้องพักเริ่มต้นให้โรงแรมละ 2 ประเภท
        await Room.create({ hotel_id: createdHotel.hotel_id, room_name: '101', room_type: 'Standard', price_per_night: 1200, max_occupancy: 2 });
        await Room.create({ hotel_id: createdHotel.hotel_id, room_name: '201', room_type: 'Deluxe', price_per_night: 2500, max_occupancy: 2 });
    }

    app.listen(3000, () => console.log('✅ Backend API -> http://localhost:3000'));
});


// ==========================================
// API สรุปข้อมูล Dashboard สำหรับ Admin
// ==========================================
app.get('/api/admin/dashboard-stats', auth, isAdmin, async (req, res) => {
    try {
        const stats = await Booking.findAll({
            attributes: [
                'status',
                [sequelize.fn('COUNT', sequelize.col('booking_id')), 'count']
            ],
            include: [{
                model: Room,
                attributes: ['hotel_id'],
                include: [{
                    model: Hotel,
                    attributes: ['hotel_name']
                }]
            }],
            group: ['Room.hotel_id', 'status', 'Room.Hotel.hotel_id']
        });
        res.json(stats);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});