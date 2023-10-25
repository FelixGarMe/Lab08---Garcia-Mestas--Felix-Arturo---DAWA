require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const { check, validationResult } = require('express-validator');
const usersRouter = require('./routes/users');

const app = express();

mongoose.connect(process.env.MONGODB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected!'))
  .catch((error) => console.error('MongoDB connection error:', error));

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: false }));
app.use('/users', usersRouter);

app.get('/', (req, res) => {
  res.redirect('/users');
});

// Middleware para encriptar contraseñas antes de almacenarlas en la base de datos
app.use(async (req, res, next) => {
  if (req.body.password) {
    try {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(req.body.password, salt);
      req.body.password = hashedPassword;
    } catch (error) {
      console.error('Error en la encriptación de la contraseña:', error);
    }
  }
  next();
});

// Middleware para validar datos del formulario
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

// Definir reglas de validación para el formulario de usuario
const userValidationRules = [
  check('name').notEmpty().withMessage('El nombre es requerido'),
  check('email').isEmail().withMessage('Ingrese un correo electrónico válido'),
  check('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres'),
];

app.post('/users', userValidationRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  // Si no hay errores de validación, guarda los datos del usuario en la base de datos
  // y redirige a la página de usuarios
  // ...
});

app.listen(process.env.PORT, () => {
  console.log(`Server started on port ${process.env.PORT}`);
});
