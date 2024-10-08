<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="ISO-8859-1">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manager Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #159957, #155799);
        }
        .dashboard-container {
            background-color: #fff;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.2);
            border-radius: 12px;
            width: 900px;
            text-align: center;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
        }
        .dashboard-container h1 {
            width: 100%;
            margin-bottom: 30px;
            color: #333;
        }
        .form-container {
            width: 45%;
            margin-bottom: 20px;
        }
        .form-container input[type="text"],
        .form-container input[type="submit"],
        .form-container select {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 6px;
            box-sizing: border-box;
        }
        .form-container input[type="submit"] {
            background-color: #007bff;
            color: white;
            border: none;
            cursor: pointer;
        }
        .form-container input[type="submit"]:hover {
            background-color: #0056b3;
        }
        .form-container .dropdown {
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <h1>Manager Dashboard</h1>

        <!-- Show Team -->
        <div class="form-container">
            <form action="webapi/manager/showTeam" method="post">
                <input type="submit" value="Show Team">
            </form>
        </div>

        <!-- Get Team Member by Username -->
        <div class="form-container">
            <form action="webapi/manager/getMember" method="post">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="submit" value="Get Team Member">
            </form>
        </div>

        <!-- Request for Admin/Assign Manager -->
        <div class="form-container">
            <form action="webapi/manager/requestAdmin" method="post">
                <input type="text" name="username" placeholder="Enter Username" required><br>
                <input type="submit" value="Assign Manager Role">
            </form>
        </div>

        <!-- Check Resources -->
        <div class="form-container">
            <form action="webapi/manager/checkResources" method="post">
                <input type="submit" value="Check Resources">
            </form>
        </div>

        <!-- Request New Resources -->
        <div class="form-container">
            <form action="webapi/manager/requestResources" method="post">
                <input type="text" name="resourceName" placeholder="Resource Name" required><br>
                <input type="submit" value="Request New Resources">
            </form>
        </div>

        <!-- Check Approvals -->
        <div class="form-container">
            <form action="webapi/manager/checkApprovals" method="post">
                <div class="dropdown">
                    <select name="approvalType" required>
                        <option value="">Select Approval Type</option>
                        <option value="resourceApproval">Resource Approval</option>
                        <option value="roleApproval">Role Approval</option>
                    </select>
                </div>
                <input type="submit" value="Check Approvals">
            </form>
        </div>

        <!-- Remove Own Resources -->
        <div class="form-container">
            <form action="webapi/manager/removeResources" method="post">
                <div class="dropdown">
                    <select name="resourceToRemove" required>
                        <option value="">Select Resource to Remove</option>
                        <option value="resource1">Resource 1</option>
                        <option value="resource2">Resource 2</option>
                        <option value="resource3">Resource 3</option>
                        <!-- Add more options as needed -->
                    </select>
                </div>
                <input type="submit" value="Remove own Resource">
            </form>
        </div>
        <div class="message">
            <%= request.getParameter("message") != null ? request.getParameter("message") : "" %>
        </div>
    </div>
</body>
</html>