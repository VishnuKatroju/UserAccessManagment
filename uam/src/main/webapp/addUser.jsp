<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="ISO-8859-1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <style>
        body {
            font-family: times new roman, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            
        }
        .register-container {
            background-color: #fff;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.2);
            border-radius: 12px;
            width: 350px;
            text-align: center;
            background: linear-gradient(135deg, rgba(255, 175, 189, 0.9), rgba(255, 195, 160, 0.9), rgba(33, 147, 176, 0.9), rgba(109, 213, 237, 0.9));
        }
        .register-container h1 {
            margin-bottom: 30px;
            color: #333;
        }
        .register-container input[type="text"],
        .register-container input[type="email"],
        .register-container input[type="password"] {
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 6px;
            box-sizing: border-box;
        }
        .register-container input[type="submit"] {
            width: 100%;
            background-color: #007bff;
            color: white;
            padding: 15px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
        }
        .register-container input[type="submit"]:hover {
            background-color: #0056b3;
        }
        .message {
            color: red;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="register-container">
        <h1>Adding New User</h1>
        <form action="webapi/myresource/addUser" method="post">
            <input type="text" name="firstname" placeholder="First Name" required><br>
            <input type="text" name="lastname" placeholder="Last Name" required><br>
            
            <input type="email" name="email" placeholder="Email" required><br>
            <input type="submit" value="Add User">
        </form>
        <div class="message">
            <%= request.getParameter("message") != null ? request.getParameter("message") : "" %>
        </div>
        
        
    </div>
</body>
</html>