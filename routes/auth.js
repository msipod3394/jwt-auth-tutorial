// 認証に関するAPI設定
const router = require("express").Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const { User } = require("../DB/User");
const JWT = require("jsonwebtoken");

router.get("/", (req, res) => {
  res.send("Hello Authjs");
});

// ユーザー新規登録用のAPI
router.post(
  "/register",

  // バリデーションチェック
  body("email").isEmail(),
  body("password").isLength({ min: 6 }),

  async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    // エラーがある場合
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    // DBにユーザーが存在しているか確認
    const user = User.find((user) => user.email === email);
    if (user) {
      return res.status(400).json([
        {
          message: "すでにそのユーザーは存在しています",
        },
      ]);
    } else {
      console.log(email, password);
    }

    // パスワードの暗号化
    let hashedPassword = await bcrypt.hash(password, 10);
    // console.log(hashedPassword);

    // DBへ保存
    User.push({
      email,
      password: hashedPassword,
    });

    // クライアントへJWTの発行
    const token = await JWT.sign(
      {
        email,
      },
      "SECRET_KEY",
      {
        expiresIn: "24h", // どのくらいの期間保存するか
      }
    );

    // クライアントにTOKENを返す
    return res.json({
      token: token,
    });
  }
);

// ログイン用のAPI
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = User.find((user) => user.email === email);

  if (!user) {
    return res.status(400).json([
      {
        msg: "そのユーザーは存在しません",
      },
    ]);
  }

  //パスワード照合
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(400).json([
      {
        msg: "パスワードが違います",
      },
    ]);
  }

  const token = await JWT.sign(
    {
      email,
    },
    "SECRET_KEY",
    { expiresIn: 60 }
  );

  return res.json({
    token: token,
  });
});
// router.post("login", async (req, res) => {
//   const { email, password } = req.body;

//   // DBにユーザーが存在しているか確認
//   const user = User.find((user) => user.email === email);
//   if (!user) {
//     return res.status(400).json([
//       {
//         message: "すでにそのユーザーは存在していません",
//       },
//     ]);
//   }

//   // パスワードのパスワードの復号・照合
//   const isMatch = await bcrypt.compare(password, user.password);
//   if (!isMatch) {
//     return res.status(400).json([
//       {
//         message: "パスワードが異なります",
//       },
//     ]);
//   }

//   // クライアントへJWTの発行
//   const token = await JWT.sign(
//     {
//       email,
//     },
//     "SECRET_KEY",
//     {
//       expiresIn: "24h", // どのくらいの期間保存するか
//     }
//   );

//   // クライアントにTOKENを返す
//   return res.json({
//     token: token,
//   });
// });

// DBのユーザーを確認するAPI
router.get("/allUsers", (req, res) => {
  return res.json(User);
});

module.exports = router;
