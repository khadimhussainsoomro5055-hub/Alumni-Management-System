const express = require("express");
const path = require("path");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const multer = require("multer");
const fs = require("fs");

const app = express();
const PORT = 3000;

const db = mysql.createConnection({
  host: "localhost",
  port: 3306,
  user: "root",
  password: "Soomro114",
  database: "alumni_system"
});

db.connect(err => {
  if (err) console.error("MySQL connection failed:", err.message);
  else console.log("Connected to MySQL: alumni_system");
});

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
  secret: "alumni-connect-secret",
  resave: false,
  saveUninitialized: false
}));

const uploadDir = path.join(__dirname, "public", "uploads", "profiles");
fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `profile-${Date.now()}-${Math.round(Math.random()*1e9)}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/webp"];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Only JPG, PNG and WEBP images are allowed."));
  }
});

function auth(req,res,next){
  if(!req.session.user) return res.redirect("/signin");
  next();
}

app.use((req,res,next)=>{
  res.locals.currentPath=req.path;
  res.locals.sessionUser=req.session.user || null;
  next();
});

app.get("/",(req,res)=>res.redirect(req.session.user?"/dashboard":"/signin"));

app.get("/signup",(req,res)=>res.render("signup",{title:"Create Account",error:null}));

app.post("/signup",async(req,res)=>{
  const {full_name,email,graduation_year,department,password}=req.body;
  if(!full_name||!email||!graduation_year||!department||!password)
    return res.status(400).render("signup",{title:"Create Account",error:"Please fill all fields."});
  try{
    const [exists]=await db.promise().execute("SELECT id FROM alumni WHERE email=?",[email.trim().toLowerCase()]);
    if(exists.length) return res.status(409).render("signup",{title:"Create Account",error:"Email already registered."});
    const hash=await bcrypt.hash(password,10);
    await db.promise().execute(
      "INSERT INTO alumni(full_name,email,graduation_year,department,password) VALUES(?,?,?,?,?)",
      [full_name.trim(),email.trim().toLowerCase(),graduation_year,department.trim(),hash]
    );
    res.redirect("/signin?registered=1");
  }catch(e){
    console.error(e);
    res.status(500).render("signup",{title:"Create Account",error:"Unable to create account."});
  }
});

app.get("/signin",(req,res)=>{
  if(req.session.user) return res.redirect("/dashboard");
  res.render("signin",{title:"Sign In",error:null,message:req.query.registered?"Account created successfully. Please sign in.":null});
});

app.post("/signin",async(req,res)=>{
  const {email,password}=req.body;
  try{
    const [rows]=await db.promise().execute("SELECT * FROM alumni WHERE email=? LIMIT 1",[email.trim().toLowerCase()]);
    if(!rows.length) return res.render("signin",{title:"Sign In",error:"Invalid email or password.",message:null});
    const user=rows[0];
    if(!(await bcrypt.compare(password,user.password)))
      return res.render("signin",{title:"Sign In",error:"Invalid email or password.",message:null});
    req.session.user={id:user.id,full_name:user.full_name,email:user.email,profile_photo:user.profile_photo};
    res.redirect("/dashboard");
  }catch(e){
    console.error(e);
    res.status(500).render("signin",{title:"Sign In",error:"Database error.",message:null});
  }
});

app.get("/logout",(req,res)=>req.session.destroy(()=>res.redirect("/signin")));

app.get("/dashboard",auth,async(req,res)=>{
  try{
    const [[stats]]=await db.promise().query(`
      SELECT
      (SELECT COUNT(*) FROM alumni) total_alumni,
      (SELECT COUNT(*) FROM events) total_events,
      (SELECT COUNT(*) FROM jobs) total_jobs
    `);
    const [recent]=await db.promise().query(
      "SELECT id,full_name,department,graduation_year,profile_photo FROM alumni ORDER BY id DESC LIMIT 5"
    );
    res.render("dashboard",{title:"Dashboard",stats,recent});
  }catch(e){console.error(e);res.status(500).send("Unable to load dashboard.");}
});

app.get("/alumni",auth,async(req,res)=>{
  const search=(req.query.search||"").trim();
  try{
    let sql=`SELECT id,full_name,email,phone,department,graduation_year,current_job,company,city,country,profile_photo FROM alumni`;
    const params=[];
    if(search){
      sql+=` WHERE full_name LIKE ? OR email LIKE ? OR department LIKE ? OR current_job LIKE ? OR city LIKE ?`;
      const s=`%${search}%`; params.push(s,s,s,s,s);
    }
    sql+=" ORDER BY id DESC";
    const [alumni]=await db.promise().execute(sql,params);
    res.render("alumni",{title:"Alumni Directory",alumni,search});
  }catch(e){console.error(e);res.status(500).send("Unable to load alumni.");}
});

app.get("/profile",auth,async(req,res)=>{
  try{
    const [rows]=await db.promise().execute("SELECT * FROM alumni WHERE id=?",[req.session.user.id]);
    if(!rows.length) return res.status(404).send("Profile not found.");
    res.render("profile",{title:"My Profile",profile:rows[0],message:req.query.updated?"Profile updated successfully.":null});
  }catch(e){console.error(e);res.status(500).send("Unable to load profile.");}
});

app.post("/profile",auth,upload.single("profile_photo"),async(req,res)=>{
  const p=req.body;
  try{
    const [oldRows]=await db.promise().execute("SELECT profile_photo FROM alumni WHERE id=?",[req.session.user.id]);
    let photo=oldRows[0]?.profile_photo || null;
    if(req.file){
      if(photo){
        const old=path.join(__dirname,"public",photo.replace(/^\//,""));
        if(fs.existsSync(old)) fs.unlinkSync(old);
      }
      photo="/uploads/profiles/"+req.file.filename;
    }
    await db.promise().execute(`
      UPDATE alumni SET full_name=?,phone=?,gender=?,date_of_birth=?,student_id=?,
      degree=?,department=?,graduation_year=?,current_job=?,company=?,city=?,country=?,
      address=?,profile_photo=? WHERE id=?`,
      [p.full_name,p.phone||null,p.gender||null,p.date_of_birth||null,p.student_id||null,
       p.degree||null,p.department,p.graduation_year,p.current_job||null,p.company||null,
       p.city||null,p.country||"Pakistan",p.address||null,photo,req.session.user.id]
    );
    req.session.user.full_name=p.full_name;
    req.session.user.profile_photo=photo;
    res.redirect("/profile?updated=1");
  }catch(e){console.error(e);res.status(500).send("Unable to update profile.");}
});

app.get("/events",auth,async(req,res)=>{
  try{
    const [events]=await db.promise().query("SELECT * FROM events ORDER BY event_date ASC");
    res.render("events",{title:"Events",events});
  }catch(e){res.status(500).send("Unable to load events.");}
});

app.get("/jobs",auth,async(req,res)=>{
  try{
    const [jobs]=await db.promise().query("SELECT * FROM jobs ORDER BY posted_at DESC");
    res.render("jobs",{title:"Jobs & Opportunities",jobs});
  }catch(e){res.status(500).send("Unable to load jobs.");}
});

app.use((err,req,res,next)=>{
  console.error(err);
  if(err instanceof multer.MulterError || err.message?.includes("images are allowed")){
    return res.status(400).send(err.message || "Image upload failed.");
  }
  res.status(500).send("Something went wrong.");
});

app.use((req,res)=>res.status(404).send("Page not found."));

app.listen(PORT,()=>console.log(`Server listening on http://localhost:${PORT}`));
