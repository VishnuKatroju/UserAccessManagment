<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="ISO-8859-1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Successful</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            }
        .success-container {
            background: linear-gradient(135deg, rgba(255, 175, 189, 0.9), rgba(255, 195, 160, 0.9), rgba(33, 147, 176, 0.9), rgba(109, 213, 237, 0.9));
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.2);
            border-radius: 12px;
            width: 350px;
            text-align: center;
        }
        .success-container h1 {
            margin-bottom: 30px;
            color: #333;
        }
        .success-container .message {
            margin-bottom: 20px;
        }
        .success-container button {
            background-color: #007bff;
            color: white;
            padding: 15px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .success-container button:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="success-container">
        <h1>Registration Successful</h1>
        <div class="message">
        <%= request.getParameter("message") %><br>
            The username is:<h2> <%= request.getParameter("username") %></h2>	
        </div>
        
    </div> 
    
        
    
</body>
</html>