// File: src/index.ts

import express, { NextFunction } from 'express';
import mysql from 'mysql2/promise';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import cors from 'cors';
dotenv.config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cors({
    origin: '*', // Replace with your specific origin
    methods: 'GET,POST',
    allowedHeaders: 'Content-Type',
}));

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: 10,
});

app.post('/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);


        const [result] = await pool.execute(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword]
        );

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error creating user', message: error });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const [rows] = await pool.execute(
            'SELECT * FROM users WHERE username = ?',
            [username]
        ) as Array<any>;

        if (rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Error logging in' });
    }
});


// New endpoint to create or update banner
app.post('/banner', async (req: express.Request, res: express.Response) => {
    try {
        const { title, description, timer, url, id } = req.body;

        //check if all required fields are provided
        if (!title || !description || !timer || !url || !id) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        //check if a banner with the same id already exists
        const [rows]: any = await pool.execute(
            'SELECT * FROM banners WHERE id = ?',
            [id]
        );
        if(rows.length !== 0) {
            return res.status(409).json({ error: 'Banner with the same ID already exists' });
        }

        await pool.execute(
            'INSERT INTO banners (id, title, description, timer, url) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE title = VALUES(title), description = VALUES(description), timer = VALUES(timer), url = VALUES(url)',
            [id, title, description, timer, url]
        );

        res.status(200).json({ message: 'Banner created successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error creating banner' });
    }
});

// New endpoint to get banner details
app.get('/banner', async (req:express.Request, res) => {
    try {
        const id = req.query.id;

        if(!id) {
            return res.status(400).json({ error: 'Banner ID is required' });
        }

        const [rows]: any = await pool.execute(
            'SELECT title, description, timer, url FROM banners WHERE id = ?',
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Banner not found' });
        }

        res.json(rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Error retrieving banner' });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
