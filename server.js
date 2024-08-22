require("dotenv").config();
const express = require("express");
const { Sequelize } = require("sequelize");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");
const path = require("path");

const app = express();

app.use(express.json());
app.use(cors());

const secretKey = process.env.JWT_SECRET || "your_secret_key";

const port = process.env.PORT || 3306;

const sequelize = new Sequelize(
  process.env.DB_NAME || "b7mnngmripovf9lushzk",
  process.env.DB_USER || "uocdbukigtlceh3l",
  process.env.DB_PASSWORD || "ZG1vqlcbbH9II3aw9xno",
  {
    host:
      process.env.DB_HOST ||
      "b7mnngmripovf9lushzk-mysql.services.clever-cloud.com",
    dialect: "mysql",
  }
);

const transporter = nodemailer.createTransport({
  service: "Gmail", // Puedes cambiar esto dependiendo de tu proveedor de correo
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const sendEmail = async (to, subject, htmlContent) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to,
    subject,
    html: htmlContent, // Cambiado de 'text' a 'htm
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Correo enviado a:", to);
  } catch (error) {
    console.error("Error al enviar el correo:", error);
  }
};

sequelize
  .authenticate()
  .then(() => console.log("Conectado a la base de datos"))
  .catch((err) => console.log("Error al conectar a la base de datos:", err));

sequelize
  .sync()
  .then(() => console.log("Modelos sincronizados"))
  .catch((err) => console.log("Error al sincronizar los modelos:", err));

// Rutas de la API
app.post("/api/auth/register", async (req, res) => {
  const { nombre, email, password } = req.body;

  try {
    let user = await sequelize.query("SELECT * FROM clientes WHERE email = ?", {
      replacements: [email],
      type: sequelize.QueryTypes.SELECT,
    });

    if (user.length > 0) {
      return res.status(400).json({ error: "El email ya está registrado" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    await sequelize.query(
      "INSERT INTO clientes (nombre, email, contraseña, fecha_registro) VALUES (?, ?, ?, NOW())",
      {
        replacements: [nombre, email, hashedPassword],
        type: sequelize.QueryTypes.INSERT,
      }
    );
    // Si el correo se envía con éxito
    res.status(201).json({
      message:
        "Usuario registrado exitosamente. Por favor, verifica tu correo electrónico.",
    });
  } catch (error) {
    // Si ocurre un error al enviar el correo, informar pero no enviar otra respuesta
    console.error("Error al enviar el correo:", error);
  }
  const token = jwt.sign({ email }, secretKey, { expiresIn: "1h" });
  const verificationLink = `http://localhost:3000/confirmacion-verificacion?token=${token}`;

  // Intentar enviar el correo electrónico
  try {
    await sendEmail(
      email,
      "Verificación de correo electrónico",
      `
        <div style="width: 100%; font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px; margin: 0;">
          <div style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">
            <h2 style="color: #333333; text-align: center;">Verificación de correo electrónico</h2>
            <p style="color: #555555; font-size: 16px;">Hola ${nombre},</p>
            <p style="color: #555555; font-size: 16px;">Por favor verifica tu correo haciendo clic en el siguiente boton:</p>
            <div style="text-align: center; margin: 20px 0;">
              <a href="${verificationLink}" style="background-color: #28a745; color: #ffffff; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-size: 16px; display: inline-block;">Verificar Correo</a>
            </div>
          </div>
        </div>
        `
    );
  } catch (err) {
    res.status(500).json({ error: "Error en el registro de usuario" });
  }
});

app.get("/api/auth/verify-email", async (req, res) => {
  const { token } = req.query;

  try {
    const decoded = jwt.verify(token, secretKey);
    console.log("Token decodificado:", decoded);
    const email = decoded.email;

    // Ejecutar la consulta SQL para actualizar el email_verificado
    const [results, metadata] = await sequelize.query(
      "UPDATE clientes SET email_verificado = 1 WHERE email = ?",
      {
        replacements: [email],
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    // Imprimir `metadata` para ver qué contiene
    console.log("Metadata después de la actualización:", metadata);

    // Verificar si alguna fila fue afectada
    const filasAfectadas = metadata; // Aquí asumimos que `metadata` es el número de filas afectadas

    if (filasAfectadas > 0) {
      res.json({ success: true, message: "Email verificado exitosamente" });
    } else {
      res.status(400).json({
        success: false,
        message: "No se encontró el email en la base de datos.",
      });
    }
  } catch (error) {
    console.error(
      "Error en la verificación del correo electrónico:",
      error.message
    );
    res.status(400).json({
      success: false,
      message: "Enlace de verificación inválido o expirado.",
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Buscar en la tabla de clientes
    let user = await sequelize.query("SELECT * FROM clientes WHERE email = ?", {
      replacements: [email],
      type: sequelize.QueryTypes.SELECT,
    });

    // Si no se encuentra, buscar en la tabla de personal de ventas
    if (user.length === 0) {
      user = await sequelize.query(
        "SELECT * FROM personal_ventas WHERE email = ?",
        {
          replacements: [email],
          type: sequelize.QueryTypes.SELECT,
        }
      );
    }

    // Si no se encuentra el usuario en ninguna tabla
    if (user.length === 0) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const foundUser = user[0];

    // Verificar la contraseña
    const isMatch = await bcrypt.compare(password, foundUser.contraseña);
    if (!isMatch) {
      return res.status(400).json({ error: "Contraseña incorrecta" });
    }

    // Verificar si el correo está verificado (solo para clientes)
    if (foundUser.id_cliente && !foundUser.email_verificado) {
      return res
        .status(403)
        .json({ error: "Correo electrónico no verificado" });
    }

    // Crear el token
    const token = jwt.sign(
      {
        id: foundUser.id_cliente || foundUser.id_personal,
      },
      secretKey,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Inicio de sesión exitoso",
      token,
      id_cliente: foundUser.id_cliente || null,
      id_personal: foundUser.id_personal || null,
    });
  } catch (err) {
    console.error("Error en el inicio de sesión:", err);
    res.status(500).json({ error: "Error en el inicio de sesión" });
  }
});

app.post("/estado-cuenta/:idCliente", async (req, res) => {
  const idCliente = req.params.idCliente;

  try {
    const pedidos = await sequelize.query(
      `SELECT p.id_pedido, p.fecha_pedido, p.total, h.fecha_entrega
       FROM pedidos p
       INNER JOIN historico_pedidos h ON p.id_pedido = h.id_pedido
       INNER JOIN estado_pedidos e ON p.id_estado = e.id_estado
       WHERE p.id_cliente = :idCliente AND e.estado_nombre = 'entregado'
       ORDER BY p.fecha_pedido DESC`,
      {
        replacements: { idCliente: idCliente },
        type: sequelize.QueryTypes.SELECT,
      }
    );
    res.json(pedidos);
  } catch (error) {
    console.error("Error al obtener el estado de cuenta:", error);
    res.status(500).send("Error en el servidor");
  }
});

app.get("/api/pro", async (req, res) => {
  const { categoriaId } = req.query; // Asegúrate de que estás usando `categoriaId` en lugar de `categoria`

  try {
    let query = "SELECT * FROM productos";
    const replacements = [];

    if (categoriaId) {
      query += ` INNER JOIN subcategorias ON productos.id_subcategoria = subcategorias.id_subcategoria WHERE subcategorias.id_categoria = ?`;
      replacements.push(categoriaId);
    }

    const productos = await sequelize.query(query, {
      type: sequelize.QueryTypes.SELECT,
      replacements,
    });

    console.log(productos);
    res.status(200).json(productos);
  } catch (err) {
    console.error("Error al obtener los productos:", err);
    res.status(500).json({ error: "Error al obtener los productos" });
  }
});

app.post("/api/auth/venta", async (req, res) => {
  const { id_cliente, productos, total, metodo_pago_id } = req.body;

  if (!id_cliente || !productos || !total || !metodo_pago_id) {
    return res.status(400).json({ error: "Faltan datos necesarios" });
  }

  const transaction = await sequelize.transaction();

  try {
    // Insertar en la tabla pedidos
    const [resultPedido] = await sequelize.query(
      "INSERT INTO pedidos (id_cliente, fecha_pedido, total, id_estado) VALUES (?, NOW(), ?, ?)",
      {
        replacements: [id_cliente, total, 1], // 1 es el id_estado para 'pendiente'
        transaction,
        type: sequelize.QueryTypes.INSERT,
      }
    );

    const id_pedido = resultPedido;

    // Preparar los datos para la tabla pedido_productos
    const productosData = productos.map((p) => [
      id_pedido,
      p.id_producto,
      p.cantidad,
      p.precio_unitario,
    ]);

    // Insertar en la tabla pedido_productos
    await sequelize.query(
      "INSERT INTO pedido_productos (id_pedido, id_producto, cantidad, precio_unitario) VALUES ?",
      {
        replacements: [productosData],
        transaction,
        type: sequelize.QueryTypes.INSERT,
      }
    );

    // Descontar el stock de los productos
    for (const producto of productos) {
      await sequelize.query(
        "UPDATE productos SET stock = stock - ? WHERE id_producto = ?",
        {
          replacements: [producto.cantidad, producto.id_producto],
          transaction,
          type: sequelize.QueryTypes.UPDATE,
        }
      );
    }

    // Insertar en la tabla ventas
    await sequelize.query(
      "INSERT INTO ventas (id_pedido, monto_total, metodo_pago_id) VALUES (?, ?, ?)",
      {
        replacements: [id_pedido, total, metodo_pago_id],
        transaction,
        type: sequelize.QueryTypes.INSERT,
      }
    );

    // Confirmar la transacción
    await transaction.commit();

    // Responder al cliente inmediatamente
    res.status(201).json({ message: "Venta registrada exitosamente" });

    // Enviar el correo electrónico en segundo plano
    const cliente = await sequelize.query(
      "SELECT email FROM clientes WHERE id_cliente = ?",
      {
        replacements: [id_cliente],
        type: sequelize.QueryTypes.SELECT,
      }
    );

    const clienteEmail = cliente[0]?.email;

    if (clienteEmail) {
      sendEmail(
        clienteEmail,
        "Tu compra está en proceso - Instrucciones para completar el pago",
        `
        <div style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
          <div style="max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);">
            <h2 style="text-align: center; color: #007BFF;">Tu compra está en proceso</h2>
            <p>Estimado cliente,</p>
            <p>Nos complace informarte que tu compra ha sido procesada exitosamente y está en proceso de confirmación.</p>
            <h3 style="color: #007BFF;">Detalles de la compra:</h3>
            <ul style="list-style-type: none; padding: 0;">
              <li><strong>ID del pedido:</strong> ${id_pedido}</li>
              <li><strong>Total a pagar:</strong> ${total}</li>
              <li><strong>Método de pago:</strong> Transferencia bancaria</li>
            </ul>
            <p>Para completar tu compra, por favor sigue los siguientes pasos:</p>
            <ol style="padding-left: 20px;">
              <li>
                <strong>Realiza un depósito</strong> del monto total a la siguiente cuenta bancaria:
                <ul style="list-style-type: none; padding: 0; margin-top: 10px;">
                  <li><strong>Banco:</strong> [Nombre del Banco]</li>
                  <li><strong>Número de cuenta:</strong> [Número de cuenta]</li>
                  <li><strong>Titular:</strong> [Nombre del titular de la cuenta]</li>
                </ul>
              </li>
              <li style="margin-top: 10px;">
                <strong>Envía un correo electrónico</strong> con el comprobante de pago a esta misma dirección (${clienteEmail}).
                <ul style="list-style-type: none; padding: 0; margin-top: 10px;">
                  <li>En el asunto del correo, incluye: <em>"Comprobante de pago - Pedido #${id_pedido}"</em></li>
                  <li>En el cuerpo del mensaje, por favor incluye:</li>
                  <ul style="list-style-type: disc; padding-left: 20px; margin-top: 5px;">
                    <li>Tu nombre completo</li>
                    <li>El ID del pedido: ${id_pedido}</li>
                    <li>El monto depositado</li>
                    <li>El número de referencia de la transacción (si aplica)</li>
                    <li>Código Postal</li>
                    <li>Localidad</li>
                    <li>Dirección</li>
                    <li>Número de casa/departamento</li>
                    <li>Referencia</li>
                  </ul>
                </ul>
              </li>
              <li style="margin-top: 10px;">
                <strong>Una vez verificado el pago</strong>, recibirás un correo electrónico de confirmación y procederemos con el envío de tus productos.
              </li>
            </ol>
            <p>Si tienes alguna duda o necesitas asistencia, no dudes en contactarnos respondiendo a este correo.</p>
            <p style="text-align: center; margin-top: 20px;"><strong>Gracias por tu compra.</strong></p>
            <p style="text-align: center; color: #555;">Atentamente,</p>
            <p style="text-align: center; color: #007BFF; font-weight: bold;">Sports</p>
          </div>
        </div>
        `
      ).catch((error) => console.error("Error al enviar el correo:", error));
    }
  } catch (err) {
    await transaction.rollback();
    console.error("Error al procesar la venta:", err);
    res.status(500).json({ error: "Error al registrar la venta" });
  }
});

app.get("/api/auth/carrito", async (req, res) => {
  const { id_cliente } = req.query;

  if (!id_cliente) {
    return res.status(400).json({ message: "El ID del cliente es requerido." });
  }

  try {
    const carritoRows = await sequelize.query(
      "SELECT cp.*, p.descripcion, p.precio_unitario FROM carrito_productos cp JOIN productos p ON cp.id_producto = p.id_producto WHERE cp.id_carrito = (SELECT id_carrito FROM carrito WHERE id_cliente = ?)",
      {
        replacements: [id_cliente],
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!Array.isArray(carritoRows)) {
      throw new Error("Error al recuperar los productos del carrito");
    }

    res.json({
      carrito: carritoRows,
    });
  } catch (error) {
    console.error("Error al obtener el carrito:", error);
    res.status(500).json({ message: "Error al obtener el carrito" });
  }
});

app.get("/api/metodos_pago", async (req, res) => {
  try {
    const [rows] = await promisePool.query("SELECT * FROM metodo_pago");
    res.json(rows);
  } catch (error) {
    console.error("Error al obtener los métodos de pago:", error);
    res.status(500).json({ message: "Error al obtener los métodos de pago." });
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res
      .status(401)
      .json({ error: "Token de autenticación no proporcionado" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token no válido" });
    req.user = user;
    next();
  });
}

app.get("/api/auth/compras", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  const id_cliente = req.query.id_cliente;

  if (!token) {
    return res
      .status(401)
      .json({ error: "Token de autenticación no proporcionado" });
  }

  if (!id_cliente) {
    return res.status(400).json({ error: "ID de cliente no disponible" });
  }

  try {
    // Verificar el token JWT
    jwt.verify(token, process.env.JWT_SECRET);

    // Realizar la consulta a la base de datos
    const pedidos = await sequelize.query(
      `SELECT p.id_pedido, p.fecha_pedido AS fecha_venta, p.total AS monto_total, e.estado_nombre
       FROM pedidos p
       JOIN estado_pedidos e ON p.id_estado = e.id_estado
       WHERE p.id_cliente = :id_cliente`,
      {
        replacements: { id_cliente },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    // Devolver los pedidos filtrados por cliente
    res.status(200).json(pedidos);
  } catch (err) {
    console.error("Error al obtener las compras:", err);
    res.status(500).json({ error: "Error al obtener las compras" });
  }
});

//CARGA PRODUCTOS
// Obtener todas las categorías
app.get("/api/categorias", async (req, res) => {
  try {
    const categorias = await sequelize.query("SELECT * FROM categorias", {
      type: sequelize.QueryTypes.SELECT,
    });
    res.status(200).json(categorias);
  } catch (err) {
    console.error("Error al obtener las categorías:", err);
    res.status(500).json({ error: "Error al obtener las categorías" });
  }
});

// Obtener subcategorías por ID de categoría
app.get("/api/subcategorias/:id_categoria", async (req, res) => {
  const { id_categoria } = req.params;

  try {
    const subcategorias = await sequelize.query(
      "SELECT * FROM subcategorias WHERE id_categoria = ?",
      {
        replacements: [id_categoria],
        type: sequelize.QueryTypes.SELECT,
      }
    );
    res.status(200).json(subcategorias);
  } catch (err) {
    console.error("Error al obtener las subcategorías:", err);
    res.status(500).json({ error: "Error al obtener las subcategorías" });
  }
});

// Ruta para agregar un nuevo producto
app.post("/api/productos", authenticateToken, async (req, res) => {
  const {
    codigo_producto,
    descripcion,
    precio_unitario,
    stock,
    id_subcategoria,
  } = req.body;

  try {
    await sequelize.query(
      "INSERT INTO productos (codigo_producto, descripcion, precio_unitario, stock, id_subcategoria) VALUES (?, ?, ?, ?, ?)",
      {
        replacements: [
          codigo_producto,
          descripcion,
          precio_unitario,
          stock,
          id_subcategoria,
        ],
        type: sequelize.QueryTypes.INSERT,
      }
    );
    res.status(201).json({ message: "Producto agregado exitosamente" });
  } catch (err) {
    console.error("Error al agregar el producto:", err);
    res.status(500).json({ error: "Error al agregar el producto" });
  }
});
app.get("/api/pedidos", authenticateToken, async (req, res) => {
  try {
    const pedidos = await sequelize.query(
      `SELECT p.id_pedido, p.id_cliente, c.nombre AS nombre_cliente, p.fecha_pedido, p.total, e.estado_nombre
       FROM pedidos p
       JOIN estado_pedidos e ON p.id_estado = e.id_estado
       JOIN clientes c ON p.id_cliente = c.id_cliente`, // Join para obtener el nombre del cliente
      {
        type: sequelize.QueryTypes.SELECT,
      }
    );
    res.status(200).json(pedidos);
  } catch (err) {
    console.error("Error al obtener los pedidos:", err);
    res.status(500).json({ error: "Error al obtener los pedidos" });
  }
});
// Ruta para actualizar un producto
// Ruta para actualizar un producto
app.put("/api/productos/:id_producto", async (req, res) => {
  const { id_producto } = req.params;
  const { codigo_producto, descripcion, precio_unitario, stock } = req.body;

  // Verifica que todos los campos necesarios estén presentes
  if (!codigo_producto || !descripcion || !precio_unitario || !stock) {
    return res.status(400).json({ error: "Todos los campos son necesarios" });
  }

  try {
    // Ejecutar la consulta SQL con los parámetros de reemplazo
    const result = await sequelize.query(
      `UPDATE productos
       SET codigo_producto = ?, descripcion = ?, precio_unitario = ?, stock = ?
       WHERE id_producto = ?`,
      {
        replacements: [
          codigo_producto,
          descripcion,
          precio_unitario,
          stock,
          id_producto,
        ],
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    // Verificar si se actualizó algún registro
    if (result[1] > 0) {
      res.status(200).json({ message: "Producto actualizado con éxito" });
    } else {
      res.status(404).json({ message: "Producto no encontrado" });
    }
  } catch (error) {
    console.error("Error al actualizar el producto:", error);
    res.status(500).json({ error: "Error al actualizar el producto" });
  }
});

// Ruta para eliminar un producto
app.delete("/api/productos/:id_producto", async (req, res) => {
  const { id_producto } = req.params;

  const deleteReferencesQuery =
    "DELETE FROM carrito_productos WHERE id_producto = ?";
  const deleteProductQuery = "DELETE FROM productos WHERE id_producto = ?";

  const transaction = await sequelize.transaction();

  try {
    // Eliminar las referencias en otras tablas primero
    await sequelize.query(deleteReferencesQuery, {
      replacements: [id_producto],
      transaction,
    });

    // Verificar si hay registros en `pedido_productos` que referencian al producto
    const [pedidoProductos] = await sequelize.query(
      "SELECT COUNT(*) AS count FROM pedido_productos WHERE id_producto = ?",
      {
        replacements: [id_producto],
        transaction,
      }
    );

    if (pedidoProductos[0].count > 0) {
      // Si hay registros, primero elimínalos
      await sequelize.query(
        "DELETE FROM pedido_productos WHERE id_producto = ?",
        {
          replacements: [id_producto],
          transaction,
        }
      );
    }

    // Luego, eliminar el producto de la tabla productos
    const [results] = await sequelize.query(deleteProductQuery, {
      replacements: [id_producto],
      transaction,
    });

    // Verificar si se eliminaron filas
    if (results.affectedRows > 0) {
      await transaction.commit();
      res.status(200).json({ message: "Producto eliminado con éxito" });
    } else {
      await transaction.rollback();
      res.status(404).json({ message: "Producto no encontrado" });
    }
  } catch (error) {
    await transaction.rollback();
    console.error("Error al eliminar el producto:", error);
    res.status(500).json({ error: "Error al eliminar el producto" });
  }
});

// Ruta para actualizar el estado de un pedido a 'entregado'
app.put(
  "/api/pedidos/:id_pedido/entregar",
  authenticateToken,
  async (req, res) => {
    const { id_pedido } = req.params;

    // Iniciar una transacción
    const transaction = await sequelize.transaction();

    try {
      // Actualizar el estado del pedido a 'entregado'
      await sequelize.query(
        `UPDATE pedidos
         SET id_estado = (SELECT id_estado FROM estado_pedidos WHERE estado_nombre = 'Entregado')
         WHERE id_pedido = ?`,
        {
          replacements: [id_pedido],
          transaction,
          type: sequelize.QueryTypes.UPDATE,
        }
      );

      // Obtener el email del cliente asociado con el pedido
      const cliente = await sequelize.query(
        `SELECT c.email FROM clientes c
         INNER JOIN pedidos p ON p.id_cliente = c.id_cliente
         WHERE p.id_pedido = ?`,
        {
          replacements: [id_pedido],
          transaction,
          type: sequelize.QueryTypes.SELECT,
        }
      );

      const clienteEmail = cliente[0]?.email;

      // Insertar el pedido en la tabla historico_pedidos
      await sequelize.query(
        `INSERT INTO historico_pedidos (id_pedido, fecha_entrega)
         VALUES (?, NOW())`,
        {
          replacements: [id_pedido],
          transaction,
          type: sequelize.QueryTypes.INSERT,
        }
      );

      // Confirmar la transacción
      await transaction.commit();

      // Enviar la respuesta al cliente antes de enviar el correo
      res.status(200).json({
        message: "Pedido marcado como entregado y movido a histórico",
      });

      // Enviar el correo electrónico de confirmación en segundo plano
      if (clienteEmail) {
        setImmediate(async () => {
          try {
            await sendEmail(
              clienteEmail,
              "Tu pedido ha sido entregado - Confirmación de recepción",
              `
              <div style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
                <div style="max-width: 600px; margin: auto; padding: 20px; background-color: #f9f9f9; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);">
                  <h2 style="text-align: center; color: #007BFF;">¡Tu pedido ha sido entregado!</h2>
                  <p>Estimado cliente,</p>
                  <p>Nos complace informarte que tu pedido ha sido entregado exitosamente.</p>
                  <h3 style="color: #007BFF;">Detalles de la entrega:</h3>
                  <ul style="list-style-type: none; padding: 0;">
                    <li><strong>ID del pedido:</strong> ${id_pedido}</li>
                  </ul>
                  <p>Esperamos que disfrutes de tu compra. Si tienes algún inconveniente o preguntas sobre tu pedido, por favor, responde a este correo y con gusto te asistiremos.</p>
                  <p style="text-align: center; margin-top: 20px;"><strong>¡Gracias por confiar en nosotros!</strong></p>
                  <p style="text-align: center; color: #555;">Atentamente,</p>
                  <p style="text-align: center; color: #007BFF; font-weight: bold;">Sports</p>
                </div>
              </div>
              `
            );
          } catch (error) {
            console.error("Error al enviar el correo de confirmación:", error);
          }
        });
      }
    } catch (err) {
      // En caso de error, revertir la transacción
      await transaction.rollback();
      console.error("Error al marcar el pedido como entregado:", err);
      res
        .status(500)
        .json({ error: "Error al marcar el pedido como entregado" });
    }
  }
);

// Ruta para obtener el estado de cuenta ordenado por fecha y por cliente
app.get("/api/estado-cuenta", authenticateToken, async (req, res) => {
  const { orden } = req.query; // 'fecha' o 'cliente'

  let query = "";
  if (orden === "fecha") {
    query = `SELECT p.id_pedido, p.id_cliente, p.fecha_pedido, p.total, e.estado_nombre
             FROM pedidos p
             JOIN estado_pedidos e ON p.id_estado = e.id_estado
             ORDER BY p.fecha_pedido`;
  } else if (orden === "cliente") {
    query = `SELECT p.id_pedido, p.id_cliente, p.fecha_pedido, p.total, e.estado_nombre
             FROM pedidos p
             JOIN estado_pedidos e ON p.id_estado = e.id_estado
             ORDER BY p.id_cliente`;
  } else {
    return res
      .status(400)
      .json({ error: "Orden de estado de cuenta no válido" });
  }

  try {
    const estadoCuenta = await sequelize.query(query, {
      type: sequelize.QueryTypes.SELECT,
    });
    res.status(200).json(estadoCuenta);
  } catch (err) {
    console.error("Error al obtener el estado de cuenta:", err);
    res.status(500).json({ error: "Error al obtener el estado de cuenta" });
  }
});

// Ruta para anular un pedido
app.delete("/api/pedidos/:id_pedido", authenticateToken, async (req, res) => {
  const { id_pedido } = req.params;
  try {
    await sequelize.query(
      `UPDATE pedidos
       SET id_estado = (SELECT id_estado FROM estado_pedidos WHERE estado_nombre = 'anulado')
       WHERE id_pedido = ?`,
      {
        replacements: [id_pedido],
        type: sequelize.QueryTypes.UPDATE,
      }
    );
    res.status(200).json({ message: "Pedido anulado" });
  } catch (err) {
    console.error("Error al anular el pedido:", err);
    res.status(500).json({ error: "Error al anular el pedido" });
  }
});

app.get("/api/listaproductos", authenticateToken, async (req, res) => {
  try {
    const productos = await sequelize.query(
      `SELECT p.id_producto, p.codigo_producto, p.descripcion, p.precio_unitario, p.stock, s.nombre_subcategoria 
       FROM productos p
       JOIN subcategorias s ON p.id_subcategoria = s.id_subcategoria`,
      {
        type: sequelize.QueryTypes.SELECT,
      }
    );
    res.json(productos);
  } catch (err) {
    console.error("Error al obtener los productos:", err);
    res.status(500).json({ error: "Error al obtener los productos" });
  }
});

app.get("/api/clientes", async (req, res) => {
  try {
    const clientes = await sequelize.query("SELECT * FROM clientes", {
      type: sequelize.QueryTypes.SELECT,
    });
    res.status(200).json(clientes);
  } catch (err) {
    console.error("Error al obtener los clientes:", err);
    res.status(500).json({ error: "Error al obtener los clientes" });
  }
});

app.post("/api/auth/carrito", async (req, res) => {
  const { id_cliente, id_producto, cantidad } = req.body;

  if (!id_cliente || !id_producto || cantidad == null) {
    return res.status(400).json({ message: "Datos incompletos." });
  }

  const t = await sequelize.transaction();

  try {
    // Verificar si el cliente ya tiene un carrito activo
    const carritoRows = await sequelize.query(
      "SELECT id_carrito FROM carrito WHERE id_cliente = ?",
      {
        replacements: [id_cliente],
        type: sequelize.QueryTypes.SELECT,
        transaction: t,
      }
    );

    if (!Array.isArray(carritoRows)) {
      throw new Error("Error al consultar el carrito");
    }

    let id_carrito;
    if (carritoRows.length === 0) {
      // Crear un nuevo carrito si no existe uno
      const [result] = await sequelize.query(
        "INSERT INTO carrito (id_cliente) VALUES (?)",
        {
          replacements: [id_cliente],
          type: sequelize.QueryTypes.INSERT,
          transaction: t,
        }
      );
      id_carrito = result; // Esto es el ID del carrito insertado
    } else {
      id_carrito = carritoRows[0].id_carrito;
    }

    // Verificar si el producto ya está en el carrito
    const carritoProductoRows = await sequelize.query(
      "SELECT id_carrito_producto FROM carrito_productos WHERE id_carrito = ? AND id_producto = ?",
      {
        replacements: [id_carrito, id_producto],
        type: sequelize.QueryTypes.SELECT,
        transaction: t,
      }
    );

    if (!Array.isArray(carritoProductoRows)) {
      throw new Error("Error al consultar los productos del carrito");
    }

    if (carritoProductoRows.length > 0) {
      // Actualizar la cantidad si el producto ya está en el carrito
      await sequelize.query(
        "UPDATE carrito_productos SET cantidad = cantidad + ? WHERE id_carrito = ? AND id_producto = ?",
        {
          replacements: [cantidad, id_carrito, id_producto],
          transaction: t,
        }
      );
    } else {
      // Insertar el producto en el carrito
      await sequelize.query(
        "INSERT INTO carrito_productos (id_carrito, id_producto, cantidad) VALUES (?, ?, ?)",
        {
          replacements: [id_carrito, id_producto, cantidad],
          transaction: t,
        }
      );
    }

    // Confirmar la transacción
    await t.commit();

    // Recuperar el carrito actualizado
    const updatedCarritoRows = await sequelize.query(
      "SELECT cp.*, p.descripcion, p.precio_unitario FROM carrito_productos cp JOIN productos p ON cp.id_producto = p.id_producto WHERE cp.id_carrito = ?",
      {
        replacements: [id_carrito],
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!Array.isArray(updatedCarritoRows)) {
      throw new Error("Error al recuperar el carrito actualizado");
    }

    res.json({
      message: "Producto agregado al carrito",
      carrito: updatedCarritoRows,
    });
  } catch (error) {
    await t.rollback();
    console.error("Error al agregar al carrito:", error);
    res
      .status(500)
      .json({ message: "Error al agregar el producto al carrito" });
  }
});

app.get("/api/auth/carrito", async (req, res) => {
  const { id_cliente } = req.query;

  if (!id_cliente) {
    return res.status(400).json({ message: "El ID del cliente es requerido." });
  }

  try {
    const carritoRows = await sequelize.query(
      "SELECT cp.*, p.descripcion, p.precio_unitario FROM carrito_productos cp JOIN productos p ON cp.id_producto = p.id_producto WHERE cp.id_carrito = (SELECT id_carrito FROM carrito WHERE id_cliente = ?)",
      {
        replacements: [id_cliente],
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!Array.isArray(carritoRows)) {
      throw new Error("Error al recuperar los productos del carrito");
    }

    res.json({
      carrito: carritoRows,
    });
  } catch (error) {
    console.error("Error al obtener el carrito:", error);
    res.status(500).json({ message: "Error al obtener el carrito" });
  }
});

app.delete("/api/auth/carrito/:id_carrito_producto", async (req, res) => {
  const { id_carrito_producto } = req.params;

  try {
    await sequelize.query(
      "DELETE FROM carrito_productos WHERE id_carrito_producto = ?",
      {
        replacements: [id_carrito_producto],
      }
    );
    res.json({ message: "Producto eliminado del carrito" });
  } catch (error) {
    console.error("Error al eliminar del carrito:", error);
    res
      .status(500)
      .json({ message: "Error al eliminar el producto del carrito" });
  }
});

// Ruta protegida de ejemplo
app.get("/api/protected", (req, res) => {
  const authHeader = req.header("Authorization");
  if (!authHeader) {
    return res.status(401).json({ error: "Token no proporcionado" });
  }

  const token = authHeader.replace("Bearer ", "");

  try {
    const decoded = jwt.verify(token, secretKey);
    res.status(200).json({
      message: "Acceso a ruta protegida permitido",
      userId: decoded.id,
    });
  } catch (err) {
    res.status(401).json({ error: "Token no válido o expirado" });
  }
});

app.use(express.static(path.join(__dirname, "dist")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "dist", "index.html"));
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
