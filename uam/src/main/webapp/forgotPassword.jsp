<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Forgot Password</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f0f2f5;
        }
        .forgot-password-container {
            background: linear-gradient(135deg, rgba(245, 245, 245, 0.9), rgba(224, 224, 224, 0.9));
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.2);
            border-radius: 12px;
            width: 350px;
            text-align: center;
        }
        .forgot-password-container h1 {
            margin-bottom: 30px;
            color: #333;
        }
        .forgot-password-container input[type="text"],
        .forgot-password-container input[type="email"],
        .forgot-password-container input[type="password"] {
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 6px;
            box-sizing: border-box;
        }
        .forgot-password-container .btn-form {
            width: 100%;
            background: linear-gradient(135deg, #00f2fe, #4facfe);
            color: white;
            padding: 15px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            font-weight: bold;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .forgot-password-container .btn-form:hover {
            background-color: #0056b3;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .forgot-password-container .error {
            color: red;
            margin-top: 10px;
        }
    </style>
    <script>
        function validatePasswords() {
            const password = document.getElementById('new-password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const updateButton = document.getElementById('update-password-button');
            const passwordError = document.getElementById('password-error');

            if (password !== confirmPassword) {
                passwordError.textContent = 'Passwords do not match.';
                updateButton.disabled = true;
            } else {
                passwordError.textContent = '';
                updateButton.disabled = false;
            }
        }
    </script>
</head>
<body>
    <div class="forgot-password-container">
        <h1>Forgot Password</h1>
        <form action="/uam/webapi/myresource/forgetpassword" method="POST">
            <div>
                <input type="text" id="username" name="username" placeholder="Enter Username" required>
            </div>
            <div>
                <input type="email" id="email" name="email" placeholder="Enter Email" required>
            </div>
            <div>
                <input type="password" id="new-password" name="new-password" placeholder="Enter New Password" 
                       required pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}"
                       title="Must contain at least one number, one uppercase and lowercase letter, and at least 8 or more characters"
                       oninput="validatePasswords()">
            </div>
            <div>
                <input type="password" id="confirm-password" name="confirm-password" placeholder="Confirm Password" 
                       required oninput="validatePasswords()">
            </div>
            <div id="password-error" class="error"></div>
            <div>
                <button class="btn-form" type="submit" id="update-password-button" disabled>Update Password</button>
            </div>
        </form>
    </div>
</body>
</html>
