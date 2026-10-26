const express = require("express");
const Database = require("better-sqlite3");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;

const db = new Database("DB.db");


// ======================================================
// MIDDLEWARE
// ======================================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: "discoverhealth-secret-key-2026",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax"
        }
    })
);

app.use(express.static(path.join(__dirname, "public")));


// ======================================================
// AUTHENTICATION MIDDLEWARE
// ======================================================

function requireLogin(req, res, next) {

    if (!req.session.user) {
        return res.status(401).json({
            error: "You must be logged in to perform this action."
        });
    }

    next();
}


// ======================================================
// TASK 1
// SEARCH RESOURCES BY REGION
// ======================================================

app.get("/api/resources/:region", (req, res) => {

    const region = req.params.region.trim();

    try {

        const statement = db.prepare(`
            SELECT *
            FROM healthcare_resources
            WHERE LOWER(region) = LOWER(?)
        `);

        const resources = statement.all(region);

        res.json(resources);

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Database error."
        });

    }

});


// ======================================================
// TASKS 2, 7 AND 11
// ADD RESOURCE + VALIDATION + LOGIN PROTECTION
// ======================================================

app.post("/api/resources", requireLogin, (req, res) => {

    const {
        name,
        category,
        country,
        region,
        lat,
        lon,
        description
    } = req.body;


    if (
        !name ||
        !category ||
        !country ||
        !region ||
        lat === undefined ||
        lat === null ||
        lon === undefined ||
        lon === null ||
        !description
    ) {

        return res.status(400).json({
            error: "All fields are required."
        });

    }


    if (
        typeof lat !== "number" ||
        typeof lon !== "number" ||
        !Number.isFinite(lat) ||
        !Number.isFinite(lon)
    ) {

        return res.status(400).json({
            error: "Latitude and longitude must be valid numbers."
        });

    }


    if (lat < -90 || lat > 90) {

        return res.status(400).json({
            error: "Latitude must be between -90 and 90."
        });

    }


    if (lon < -180 || lon > 180) {

        return res.status(400).json({
            error: "Longitude must be between -180 and 180."
        });

    }


    try {

        const statement = db.prepare(`
            INSERT INTO healthcare_resources
            (
                name,
                category,
                country,
                region,
                lat,
                lon,
                description,
                recommendations
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        `);


        const result = statement.run(
            name.trim(),
            category.trim(),
            country.trim(),
            region.trim(),
            lat,
            lon,
            description.trim()
        );


        const newResource = db.prepare(`
            SELECT *
            FROM healthcare_resources
            WHERE id = ?
        `).get(result.lastInsertRowid);


        res.status(201).json({
            message: "Healthcare resource added successfully.",
            resource: newResource
        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Database error."
        });

    }

});


// ======================================================
// TASK 3
// RECOMMEND RESOURCE
// ======================================================

app.post("/api/resources/:id/recommend", (req, res) => {

    const id = Number(req.params.id);

    if (!Number.isInteger(id)) {
        return res.status(400).json({
            error: "Invalid resource ID."
        });
    }


    try {

        const statement = db.prepare(`
            UPDATE healthcare_resources
            SET recommendations = recommendations + 1
            WHERE id = ?
        `);


        const result = statement.run(id);


        if (result.changes === 0) {

            return res.status(404).json({
                error: "Healthcare resource not found."
            });

        }


        const resource = db.prepare(`
            SELECT *
            FROM healthcare_resources
            WHERE id = ?
        `).get(id);


        res.json({
            message: "Healthcare resource recommended successfully.",
            resource
        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Database error."
        });

    }

});


// ======================================================
// TASK 10
// LOGIN
// ======================================================

app.post("/api/login", async (req, res) => {

    const { username, password } = req.body;


    if (!username || !password) {

        return res.status(400).json({
            error: "Username and password are required."
        });

    }


    try {

        const user = db.prepare(`
            SELECT *
            FROM users
            WHERE username = ?
        `).get(username);


        if (!user) {

            return res.status(401).json({
                error: "Invalid username or password."
            });

        }


        let passwordMatches = false;


        // Allows existing starter-database passwords to work
        // while supporting hashed passwords for newly created users.
        if (
            typeof user.password === "string" &&
            user.password.startsWith("$2")
        ) {

            passwordMatches = await bcrypt.compare(
                password,
                user.password
            );

        } else {

            passwordMatches = password === user.password;

        }


        if (!passwordMatches) {

            return res.status(401).json({
                error: "Invalid username or password."
            });

        }


        req.session.user = {
            id: user.id,
            username: user.username,
            isAdmin: user.isAdmin
        };


        res.json({
            message: "Login successful.",
            username: user.username
        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Unable to login."
        });

    }

});


// ======================================================
// TASK 10
// LOGOUT
// ======================================================

app.post("/api/logout", (req, res) => {

    req.session.destroy(error => {

        if (error) {

            return res.status(500).json({
                error: "Unable to logout."
            });

        }


        res.json({
            message: "Logged out successfully."
        });

    });

});


// ======================================================
// TASK 10
// CHECK CURRENT SESSION
// ======================================================

app.get("/api/session", (req, res) => {

    if (!req.session.user) {

        return res.json({
            loggedIn: false
        });

    }


    res.json({
        loggedIn: true,
        username: req.session.user.username
    });

});


// ======================================================
// TASK 10
// SIGNUP ROUTE
// No signup form is required by the brief
// ======================================================

app.post("/api/signup", async (req, res) => {

    const { username, password } = req.body;


    if (!username || !password) {

        return res.status(400).json({
            error: "Username and password are required."
        });

    }


    try {

        const existingUser = db.prepare(`
            SELECT id
            FROM users
            WHERE username = ?
        `).get(username);


        if (existingUser) {

            return res.status(409).json({
                error: "Username already exists."
            });

        }


        const hashedPassword = await bcrypt.hash(password, 10);


        const statement = db.prepare(`
            INSERT INTO users
            (username, password, isAdmin)
            VALUES (?, ?, 0)
        `);


        const result = statement.run(
            username.trim(),
            hashedPassword
        );


        res.status(201).json({
            message: "User created successfully.",
            id: result.lastInsertRowid
        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Unable to create user."
        });

    }

});


// ======================================================
// TASK 12
// ADD REVIEW
// ======================================================

app.post("/api/reviews", requireLogin, (req, res) => {

    const { resource_id, review } = req.body;

    const resourceId = Number(resource_id);


    if (!Number.isInteger(resourceId)) {

        return res.status(400).json({
            error: "A valid resource ID is required."
        });

    }


    if (!review || review.trim() === "") {

        return res.status(400).json({
            error: "Review cannot be empty."
        });

    }


    try {

        const resource = db.prepare(`
            SELECT id
            FROM healthcare_resources
            WHERE id = ?
        `).get(resourceId);


        if (!resource) {

            return res.status(404).json({
                error: "Healthcare resource not found."
            });

        }


        const statement = db.prepare(`
            INSERT INTO reviews
            (resource_id, review, user_id)
            VALUES (?, ?, ?)
        `);


        const result = statement.run(
            resourceId,
            review.trim(),
            req.session.user.id
        );


        res.status(201).json({
            message: "Review added successfully.",
            id: result.lastInsertRowid
        });


    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Unable to add review."
        });

    }

});


// ======================================================
// GET REVIEWS FOR A RESOURCE
// ======================================================

app.get("/api/resources/:id/reviews", (req, res) => {

    const id = Number(req.params.id);


    if (!Number.isInteger(id)) {

        return res.status(400).json({
            error: "Invalid resource ID."
        });

    }


    try {

        const reviews = db.prepare(`
            SELECT
                reviews.id,
                reviews.review,
                users.username
            FROM reviews
            JOIN users
                ON reviews.user_id = users.id
            WHERE reviews.resource_id = ?
            ORDER BY reviews.id DESC
        `).all(id);


        res.json(reviews);


    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Unable to load reviews."
        });

    }

});


// ======================================================
// START SERVER
// ======================================================

app.listen(PORT, () => {

    console.log(
        `DiscoverHealth running on http://localhost:${PORT}`
    );

});