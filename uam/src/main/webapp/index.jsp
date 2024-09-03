 <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="ISO-8859-1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            /*background: linear-gradient(135deg, #71b7e6, #9b59b6);*/
            
        }
        .message
        {
        	color:red;
        }
        .login-container {
            background-color: #fff;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.2);
            border-radius: 12px;
            width: 350px;
            text-align: center;
            transition: all 0.3s ease;
			background: linear-gradient(135deg, rgba(255, 175, 189, 0.9), rgba(255, 195, 160, 0.9), rgba(33, 147, 176, 0.9), rgba(109, 213, 237, 0.9));
        }
        .login-container:hover {
            box-shadow: 0 0 30px rgba(0,0,0,0.3);
        }
        .login-container h1 {
            margin-bottom: 30px;
            color: #333;
        }
        .login-container input[type="text"],
        .login-container input[type="password"] {
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 6px;
            box-sizing: border-box;
            transition: all 0.3s ease;
        }
        .login-container input[type="text"]:focus,
        .login-container input[type="password"]:focus {
            border-color: #9b59b6;
            box-shadow: 0 0 8px rgba(155, 89, 182, 0.6);
        }
        .login-container input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            padding: 15px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            width: 100%;
            transition: all 0.3s ease;
        }
        .login-container input[type="submit"]:hover {
            background-color: #45a049;
        }
        .login-container a {
            display: block;
            margin-top: 20px;
            color: black;
            text-decoration: none;
            transition: color 0.3s ease;
        }
        .login-container a:hover {
            color: #333;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Login</h1>
        <form action="webapi/myresource/login" method="post">
            <input type="text" name="username" placeholder="User Name" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <input type="submit" value="Submit">
        </form>
         <div class="message">
         <br>
            <%= request.getParameter("message") != null ? request.getParameter("message") : "" %>
        </div>
        <a href="/uam/register.jsp" >No Account? <span style="color:Red">Create!</span></a>
        <a href="/uam/forgotPassword.jsp">Forgot Password?</a>
    </div>
</body>
</html>
 