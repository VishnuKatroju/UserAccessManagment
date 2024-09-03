package MyProject.uam;

import java.io.*;
import java.sql.*;
import java.util.*;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


/**
 * Root resource (exposed at "myresource" path)
 */
@Path("myresource")
public class MyResource {
	

    /**
     * Method handling HTTP GET requests. The returned object will be sent
     * to the client as "text/plain" media type.
     *
     * @return String that will be returned as a text/plain response.
     */
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String getIt() {
        return "Got it!";
    }
    
    @GET
    @Path("db")
    public String db_connect() throws ClassNotFoundException, SQLException {
        Connection c = SampleDb.connect();
        if (c != null)
            return "Connected";
        else
            return "Not Connected!";
    }
    
    @GET
    @Path("fullname")
    public String gen() throws ClassNotFoundException, SQLException {
        User ob = new User("Firstname", "Lastname", null, null, null,null);
        return ob.generatefullname("vishnu.katroju");
    }

    @POST
    @Path("register")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public void register(@FormParam("firstname") String firstname,
                         @FormParam("lastname") String lastname,
                         @FormParam("email") String email,
                         @FormParam("password") String password,
                         @FormParam("confirm_password") String confirmPassword,
                         @Context HttpServletResponse response) throws IOException {
        if (!password.equals(confirmPassword)) {
            response.sendRedirect("/uam/register.jsp?message=Passwords do not match");
            return;
        }
        try {
            User ob = new User(firstname, lastname, null, email, password,null);
            ob.registerUser();
            String username = ob.getUsername(email);
            response.sendRedirect("/uam/registrationSuccess.jsp?message=Registration successful&username=" + username);
        } catch (Exception e) {
            response.sendRedirect("/uam/register.jsp?message=Registration failed: " + e.getMessage());
        }
    }

    @POST
    @Path("login")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void login(@FormParam("username") String username,
                      @FormParam("password") String password,
                      @Context HttpServletRequest request,
                      @Context HttpServletResponse response) throws IOException {
        try {
            User ob = new User(null, null, username, null, password,null);
            String loginResult = ob.login();
            String failure = "Login Failed";
            String fullname=ob.generatefullname(username);

            if ("user".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/user.html?username=" + username+"&fullname="+fullname);
            } else if ("admin".equals(loginResult) || "Admin".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/admin.html?username=" + username+"&fullname="+fullname);
            } else if ("manager".equals(loginResult) || "Manager".equals(loginResult)) {
                HttpSession session = request.getSession();
                session.setAttribute("username", username);
                response.sendRedirect("/uam/manager.html?username=" + username+"&fullname="+fullname);
            } else {
                response.sendRedirect("/uam/?message=" + failure); 
            }
        } catch (Exception e) {
            response.sendRedirect("/uam/?message=Cannot login");
        }
    }
    
    
    @POST

    @Path("logout")

    public Response logout(@Context HttpServletRequest request) {
    	
        HttpSession session = request.getSession(false);

        if (session != null) {

            session.invalidate();  // Invalidate the session

        }

        return Response.ok().build();

    }

    
    
    @GET
    @Path("checkapprovals")
    public Response checkApprovals(@Context HttpServletRequest request) throws Exception {
        Connection conn = null;
        PreparedStatement ps1 = null;
        ResultSet rs1 = null;
        StringBuilder result = new StringBuilder();

        try {
            conn = SampleDb.connect();
            String q1 = "SELECT username, request_type, request_value, status, approved FROM requests";
            ps1 = conn.prepareStatement(q1);
            rs1 = ps1.executeQuery();

            // Build a JSON-like structure using StringBuilder
            result.append("[");  // Start of JSON array

            while (rs1.next()) {
                if (result.length() > 1) {
                    result.append(",");  // Separate objects with commas
                }

                String username = rs1.getString("username");
                String requestType = rs1.getString("request_type");
                String requestValue = rs1.getString("request_value");
                int status = rs1.getInt("status");
                int approved = rs1.getInt("approved");
                String requestStatus;

                // Determine the request status based on the conditions
                if (status == 0 && approved == 0) {
                    requestStatus = "Pending";
                } else if (status == 1 && approved == 1) {
                    requestStatus = "Accepted";
                } else if (status == 1 && approved == 0) {
                    requestStatus = "Rejected";
                } else {
                    requestStatus = "Unknown";
                }

                // Add the JSON object for this record
                result.append("{")
                      .append("\"username\":\"").append(username).append("\",")
                      .append("\"request_type\":\"").append(requestType).append("\",")
                      .append("\"request_value\":\"").append(requestValue).append("\",")
                      .append("\"request_status\":\"").append(requestStatus).append("\"")
                      .append("}");
            }

            result.append("]");  // End of JSON array

        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                           .entity("Error fetching approvals").build();
        } finally {
            // Clean up resources
            if (rs1 != null) rs1.close();
            if (ps1 != null) ps1.close();
            if (conn != null) conn.close();
        }

        return Response.ok(result.toString()).build();
    }

    
    @POST
    @Path("/forgetpassword")
    @Consumes("application/x-www-form-urlencoded")
    public Response forgetPassword(
        @FormParam("username") String username,
        @FormParam("email") String email,
        @FormParam("new-password") String newPassword) {
    	User u = new User();
    	newPassword=u.encrypt(newPassword);
        Connection conn = null;
        PreparedStatement checkUserStmt = null;
        PreparedStatement updatePasswordStmt = null;

        try {
            // Establish database connection
            conn = SampleDb.connect();

            // Check if the username and email are valid
            String checkUserQuery = "SELECT * FROM users WHERE username = ? AND email = ?";
            checkUserStmt = conn.prepareStatement(checkUserQuery);
            checkUserStmt.setString(1, username);
            checkUserStmt.setString(2, email);

            ResultSet rs = checkUserStmt.executeQuery();

            if (rs.next()) {
                // Username and email are valid, update the password
                String updatePasswordQuery = "UPDATE users SET password = ? WHERE username = ?";
                updatePasswordStmt = conn.prepareStatement(updatePasswordQuery);
                updatePasswordStmt.setString(1, newPassword);  // Note: Hash the password before storing in production
                updatePasswordStmt.setString(2, username);
                updatePasswordStmt.executeUpdate();

                return Response.ok("Password updated successfully.").build();
            } else {
                // Username and email are not valid
                return Response.status(Response.Status.BAD_REQUEST)
                               .entity("Invalid username or email.").build();
            }

        } catch (SQLException e) {
            e.printStackTrace();
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        } finally {
            // Close resources in finally block to ensure they're always closed
            try {
                if (checkUserStmt != null) checkUserStmt.close();
                if (updatePasswordStmt != null) updatePasswordStmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }

    
    @GET
    @Path("checkmyapprovals")
    public Response checkMyApprovals(@Context HttpServletRequest request) throws Exception {
        Connection conn = null;
        PreparedStatement ps1 = null;
        ResultSet rs1 = null;
        StringBuilder result = new StringBuilder();

        try {
            conn = SampleDb.connect();
            HttpSession session = request.getSession();
            String username1 = (String) session.getAttribute("username");
            String q1 = "SELECT username, request_type, request_value, status, approved FROM requests where username=?";
            ps1 = conn.prepareStatement(q1);
            ps1.setString(1, username1);
            
            rs1 = ps1.executeQuery();

            // Build a JSON-like structure using StringBuilder
            result.append("[");  // Start of JSON array

            while (rs1.next()) {
                if (result.length() > 1) {
                    result.append(",");  // Separate objects with commas
                }

                String username = rs1.getString("username");
                String requestType = rs1.getString("request_type");
                String requestValue = rs1.getString("request_value");
                int status = rs1.getInt("status");
                int approved = rs1.getInt("approved");
                String requestStatus;

                // Determine the request status based on the conditions
                if (status == 0 && approved == 0) {
                    requestStatus = "Pending";
                } else if (status == 1 && approved == 1) {
                    requestStatus = "Accepted";
                } else if (status == 1 && approved == 0) {
                    requestStatus = "Rejected";
                } else {
                    requestStatus = "Unknown";
                }

                // Add the JSON object for this record
                result.append("{")
                      .append("\"username\":\"").append(username).append("\",")
                      .append("\"request_type\":\"").append(requestType).append("\",")
                      .append("\"request_value\":\"").append(requestValue).append("\",")
                      .append("\"request_status\":\"").append(requestStatus).append("\"")
                      .append("}");
            }

            result.append("]");  // End of JSON array

        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                           .entity("Error fetching approvals").build();
        } finally {
            // Clean up resources
            if (rs1 != null) rs1.close();
            if (ps1 != null) ps1.close();
            if (conn != null) conn.close();
        }

        return Response.ok(result.toString()).build();
    }
    
    @GET
    @Path("listcheck")
    public Response listgen(@Context HttpServletRequest request) throws IOException {
        List<String> list1 = new ArrayList<>(); // List to store results of q1
        List<String> list2 = new ArrayList<>(); // List to store results of q2
        List<String> onlyInList1 = new ArrayList<>(); // List to store resources only in list1
        List<String> pendingResources = new ArrayList<>(); // List to store resources with pending requests

        try {
            Connection conn = SampleDb.connect();
            HttpSession session = request.getSession();
            String username = (String) session.getAttribute("username");

            // Query 1: Get all resources
            String q1 = "SELECT resource_name FROM resources";
            PreparedStatement ps1 = conn.prepareStatement(q1);
            ResultSet rs1 = ps1.executeQuery();

            while (rs1.next()) {
                list1.add(rs1.getString("resource_name"));
            }

            // Query 2: Get resources already assigned to the user
            String q2 = "SELECT resource_name FROM user_resources WHERE username=?";
            PreparedStatement ps2 = conn.prepareStatement(q2);
            ps2.setString(1, username);
            ResultSet rs2 = ps2.executeQuery();

            while (rs2.next()) {
                list2.add(rs2.getString("resource_name"));
            }

            // Query 3: Get resources with pending requests by the user
            String q3 = "SELECT request_value FROM requests WHERE username=? AND request_type='Resource Request' AND status=0 AND approved=0";
            PreparedStatement ps3 = conn.prepareStatement(q3);
            ps3.setString(1, username);
            ResultSet rs3 = ps3.executeQuery();

            while (rs3.next()) {
                pendingResources.add(rs3.getString("request_value"));
            }

            // Create a Set for list2 for efficient lookups
            Set<String> set2 = new HashSet<>(list2);

            // Find resources in list1 but not in list2
            for (String resource : list1) {
                if (!set2.contains(resource)) {
                    onlyInList1.add(resource);
                }
            }

            // Remove resources from onlyInList1 if they have pending requests
            onlyInList1.removeAll(pendingResources);

            // Close resources
            rs1.close();
            ps1.close();
            rs2.close();
            ps2.close();
            rs3.close();
            ps3.close();
            conn.close();
        } catch (Exception e) {
            e.printStackTrace(); // Log the exception (or handle it accordingly)
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error processing request").build();
        }

        // Return the lists as part of the response
        return Response.ok(onlyInList1).build();
    }


    @POST
    @Path("requestRole")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void requestRole(@FormParam("requestedRole") String requestedRole,
                            @Context HttpServletRequest request,
                            @Context HttpServletResponse response) throws IOException {
        try {
            HttpSession session = request.getSession();
            String username = (String) session.getAttribute("username");

            if (username != null) {
                User ob = new User(null, null, username, null, null,null);
                ob.requestRole(requestedRole);
//                response.sendRedirect("/uam/roleRequestSuccess.jsp");
            } else {
                response.sendRedirect("/uam/?message=Oh! No, Session expired, please login again!!");
            }
        } catch (Exception e) {
            response.sendRedirect("/uam/user_home.jsp?message=Cannot process request");
        }
    }
    
    @POST
    @Path("managertoadmin")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public void managerToAdmin(@FormParam("teamMember") String teamMember,
                            @Context HttpServletRequest request,
                            @Context HttpServletResponse response) throws IOException {
        try {
            HttpSession session = request.getSession();
            String username = (String) session.getAttribute("username");

            if (username != null) {
                User ob = new User(null, null, username, null, null,null);
                ob.managertoadmin(teamMember);
//                response.sendRedirect("/uam/roleRequestSuccess.jsp");
            } else {
                response.sendRedirect("/uam/?message=Oh! No, Session expired, please login again!!");
            }
        } catch (Exception e) {
            response.sendRedirect("/uam/user_home.jsp?message=Cannot process request");
        }
    }
    
    @POST
    @Path("requestResources")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response requestResources(
            @FormParam("resourceName") String requestResources,
            @Context HttpServletRequest request) {
        try {
            HttpSession session = request.getSession();
            String username = (String) session.getAttribute("username");

            if (username != null) {
                User ob = new User(null, null, username, null, null, null);
                ob.requestResources(requestResources);
                return Response.ok("Resource requested successfully").build(); // Return success message
            } else {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Session expired, please login again.").build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("Resource does not exist or another error occurred.").build();
        }
    }

    @GET
    @Path("getadmin")
    public String getAdmin()
    {
    	User u = new User();
    	return u.firstAdmin;
    }

    @GET
    @Path("showrequests")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getRequests() {
        List<Request> requestlist = new ArrayList<>();
        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT * FROM requests WHERE status = 0";
            try (PreparedStatement stmt = conn.prepareStatement(query);
                 ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    String username = rs.getString("username");
                    String requestType = rs.getString("request_type");
                    String requestValue = rs.getString("request_value");
                    boolean approved = rs.getBoolean("approved");
                    requestlist.add(new Request(username, requestType, requestValue, approved));
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching requests: " + e.getMessage()).build();
        }
        return Response.ok(requestlist).build();
    }
    
    @GET
    @Path("connection")
    public String getconncet() throws Exception
    {
    	Connection conn = SampleDb.connect();
    	if(conn != null) {
    		return "connected";
    	}
    	return "Not connected";
    }
    
    @POST
    @Path("request/accept")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response acceptRequest(@FormParam("username") String username,
                                  @FormParam("requestType") String requestType,
                                  @FormParam("requestValue") String requestValue) {
        try (Connection conn = SampleDb.connect()) {
            String updateQuery = "UPDATE requests SET status = 1, approved = 1 WHERE username = ? AND request_type = ? AND request_value = ? AND  (status = 0 AND approved = 0)";
            try (PreparedStatement stmt = conn.prepareStatement(updateQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, requestType);
                stmt.setString(3, requestValue);
                stmt.executeUpdate();
                
                // Additional logic for Role Request
                if (requestType.equals("Role Request")) {
                    String updateDetailsQuery = "UPDATE users SET user_type = ?,managerID=? WHERE username = ?";
                    try (PreparedStatement updateStmt = conn.prepareStatement(updateDetailsQuery)) {
                        updateStmt.setString(1, requestValue);
                        updateStmt.setString(2, getAdmin());
                        updateStmt.setString(3, username);
                        updateStmt.executeUpdate();
                    }
                }

                // Additional logic for Resource Request
                if (requestType.equals("Resource Request")) {
                    String insertQuery = "INSERT INTO user_resources (username, resource_name) VALUES (?, ?)";
                    try (PreparedStatement insertStmt = conn.prepareStatement(insertQuery)) {
                        insertStmt.setString(1, username);
                        insertStmt.setString(2, requestValue);
                        insertStmt.executeUpdate();
                    }
                }
                
                // if manager requested to Admin Role
                if (requestValue.equals("manager-to-admin")) {
                	String newManager=User.newManager;
                    
                    // 1. Update the old manager's user_type to 'admin'
                    String updateOldManagerQuery = "UPDATE users SET user_type = 'admin' WHERE username = ?";
                    try (PreparedStatement updateOldManagerStmt = conn.prepareStatement(updateOldManagerQuery)) {
                        updateOldManagerStmt.setString(1, username);
                        updateOldManagerStmt.executeUpdate();
                    }

                    // 2. Update the new manager's user_type to 'Manager'
                    String updateNewManagerQuery = "UPDATE users SET user_type = 'Manager' WHERE username = ?";
                    try (PreparedStatement updateNewManagerStmt = conn.prepareStatement(updateNewManagerQuery)) {
                        updateNewManagerStmt.setString(1, newManager);
                        updateNewManagerStmt.executeUpdate();
                    }

                    // 3. Reassign users from the old manager to the new manager
                    String reassignUsersQuery = "UPDATE users SET managerID = ? WHERE managerID = ? and username!=?";
                    try (PreparedStatement reassignUsersStmt = conn.prepareStatement(reassignUsersQuery)) {
                        reassignUsersStmt.setString(1, newManager);
                        reassignUsersStmt.setString(2, username);
                        reassignUsersStmt.setString(3, newManager);
                        reassignUsersStmt.executeUpdate();
                    }
                    
                    //4. Set newManager's managerId to NULL
                    String setNewManagerQuery = "UPDATE users SET managerID = NULL WHERE username = ?";
                    try (PreparedStatement setNewManagerStmt = conn.prepareStatement(setNewManagerQuery)) {
                        setNewManagerStmt.setString(1, newManager);
                        setNewManagerStmt.executeUpdate();
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error accepting request: " + e.getMessage()).build();
        }
        return Response.ok("Request accepted").build();
    }

    @POST
    @Path("request/reject")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response rejectRequest(@FormParam("username") String username,
                                  @FormParam("requestType") String requestType,
                                  @FormParam("requestValue") String requestValue) {
        try (Connection conn = SampleDb.connect()) {
            String updateQuery = "UPDATE requests SET status = 1, approved = 0 WHERE username = ? AND request_type = ? AND request_value = ? AND NOT(status = 1 AND approved = 1)";
            try (PreparedStatement stmt = conn.prepareStatement(updateQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, requestType);
                stmt.setString(3, requestValue);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error rejecting request: " + e.getMessage()).build();
        }
        return Response.ok("Request rejected").build();
    }
    
    @GET
    @Path("resources")
    public Response getResources() {
        List<Resource> resources = new ArrayList<>();

        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT resource_name FROM resources";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(query)) {

                while (rs.next()) {
                    Resource resource = new Resource();
                    resource.setResourceName(rs.getString("resource_name"));
                    resources.add(resource);
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching resources: " + e.getMessage()).build();
        }

        return Response.ok(resources).build();
    }

    @POST
    @Path("resource/delete")
    @Consumes("application/x-www-form-urlencoded")
    public Response deleteResource(@FormParam("resourceName") String resourceName) {
        try (Connection conn = SampleDb.connect()) {
            conn.setAutoCommit(false);
            
            try {
                String deleteReferencesQuery = "DELETE FROM user_resources WHERE resource_name = ?";
                try (PreparedStatement stmt = conn.prepareStatement(deleteReferencesQuery)) {
                    stmt.setString(1, resourceName);
                    stmt.executeUpdate();
                }

                String deleteResourceQuery = "DELETE FROM resources WHERE resource_name = ?";
                try (PreparedStatement stmt = conn.prepareStatement(deleteResourceQuery)) {
                    stmt.setString(1, resourceName);
                    int rowsAffected = stmt.executeUpdate();
                    
                    if (rowsAffected > 0) {
                        conn.commit();
                        return Response.ok(resourceName+" deleted successfully").build();
                    } else {
                        conn.rollback();
                        return Response.status(Response.Status.NOT_FOUND).entity("Resource not found").build();
                    }
                }
            } catch (SQLException e) {
                conn.rollback();
                return Response.serverError().entity("Error deleting resource: " + e.getMessage()).build();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Database connection error: " + e.getMessage()).build();
        }
    }
    
    @GET
    @Path("userresources")
    public Response getUserResources() {
        List<UserResource> userResources = new ArrayList<>();
        
        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT username, resource_name FROM user_resources";
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(query)) {

                while (rs.next()) {
                    UserResource ur = new UserResource();
                    ur.setUsername(rs.getString("username"));
                    ur.setResourceName(rs.getString("resource_name"));
                    userResources.add(ur);
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching user resources: " + e.getMessage()).build();
        }

        return Response.ok(userResources).build();
    }

    @POST
    @Path("resource/remove")
    @Consumes("application/x-www-form-urlencoded")
    public Response removeResourceFromUser(@FormParam("username") String username,
                                           @FormParam("resourceName") String resourceName) {
        try (Connection conn = SampleDb.connect()) {
            String deleteQuery = "DELETE FROM user_resources WHERE username = ? AND resource_name = ?";
            try (PreparedStatement stmt = conn.prepareStatement(deleteQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, resourceName);
                int rowsAffected = stmt.executeUpdate();

                if (rowsAffected > 0) {
                    return Response.ok(resourceName+" removed successfully from "+username).build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("Resource or user not found").build();
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error removing resource: " + e.getMessage()).build();
        }
    }
    
    @POST
    @Path("removeuser")
    @Consumes("application/x-www-form-urlencoded")
    public Response removeUser(@FormParam("user") String username) throws Exception {
        Connection conn = null;
        PreparedStatement getUserTypeStmt = null;
        PreparedStatement updateTeamMembersStmt = null;
        PreparedStatement deleteUserResourcesStmt = null;
        PreparedStatement deleteUserRequestsStmt = null;
        PreparedStatement deleteUserStmt = null;

        try {
            conn = SampleDb.connect();
            conn.setAutoCommit(false); // Start transaction

            // Step 1: Find the user's type
            String getUserTypeQuery = "SELECT user_type FROM users WHERE username = ?";
            getUserTypeStmt = conn.prepareStatement(getUserTypeQuery);
            getUserTypeStmt.setString(1, username);
            ResultSet rs = getUserTypeStmt.executeQuery();

            String userType = "";
            if (rs.next()) {
                userType = rs.getString("user_type");
            }

            // Step 2: If the user is a manager, update their team members' managerID to null
            if (userType.equals("Manager")) {
                String updateTeamMembersQuery = "UPDATE users SET managerID = NULL WHERE managerID = ?";
                updateTeamMembersStmt = conn.prepareStatement(updateTeamMembersQuery);
                updateTeamMembersStmt.setString(1, username);
                updateTeamMembersStmt.executeUpdate();
            }

            // Step 3: Remove the user's attached resources from user_resources table
            String deleteUserResourcesQuery = "DELETE FROM user_resources WHERE username = ?";
            deleteUserResourcesStmt = conn.prepareStatement(deleteUserResourcesQuery);
            deleteUserResourcesStmt.setString(1, username);
            deleteUserResourcesStmt.executeUpdate();

            // Step 4: Remove the user's pending requests from requests table
            String deleteUserRequestsQuery = "DELETE FROM requests WHERE username = ? AND status = 0 AND approved = 0";
            deleteUserRequestsStmt = conn.prepareStatement(deleteUserRequestsQuery);
            deleteUserRequestsStmt.setString(1, username);
            deleteUserRequestsStmt.executeUpdate();

            // Step 5: Remove the user from the users table
            String deleteUserQuery = "DELETE FROM users WHERE username = ?";
            deleteUserStmt = conn.prepareStatement(deleteUserQuery);
            deleteUserStmt.setString(1, username);
            deleteUserStmt.executeUpdate();

            // Commit the transaction
            conn.commit();

            return Response.ok(username+" and associated records removed successfully.").build();
        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback(); // Rollback in case of error
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            return Response.serverError().entity("Failed to remove user: " + e.getMessage()).build();
        } finally {
            // Close resources in the finally block to ensure they're always closed
            if (getUserTypeStmt != null) {
                try {
                    getUserTypeStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (updateTeamMembersStmt != null) {
                try {
                    updateTeamMembersStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (deleteUserResourcesStmt != null) {
                try {
                    deleteUserResourcesStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (deleteUserRequestsStmt != null) {
                try {
                    deleteUserRequestsStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (deleteUserStmt != null) {
                try {
                    deleteUserStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }


    
    @POST
    @Path("checkresources")
    @Consumes("application/x-www-form-urlencoded")
    public Response checkResources(@FormParam("userrr") String username) {
        List<String> resources = new ArrayList<>();
        
        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT resource_name FROM user_resources WHERE username = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, username);
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        resources.add(rs.getString("resource_name"));
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching resources: " + e.getMessage()).build();
        }

        StringBuilder responseHtml = new StringBuilder("<h3>Resources for user: " + username + "</h3>");
        if (resources.isEmpty()) {
            responseHtml.append("<p>No resources found for the user.</p>");
        } else {
            responseHtml.append("<ul>");
            for (String resource : resources) {
                responseHtml.append("<li>").append(resource).append("</li>");
            }
            responseHtml.append("</ul>");
        }

        // Return HTML content to be displayed on the same page
        return Response.ok(responseHtml.toString()).build();
    }
    
    @POST
    @Path("checkusers")
    @Consumes("application/x-www-form-urlencoded")
    public Response checkUsers(@FormParam("resource") String resourceName) {
        List<String> users = new ArrayList<>();
        
        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT username FROM user_resources WHERE resource_name = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.setString(1, resourceName);
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        users.add(rs.getString("username"));
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error fetching users: " + e.getMessage()).build();
        }

        StringBuilder responseHtml = new StringBuilder("<h3>Users with resource: " + resourceName + "</h3>");
        if (users.isEmpty()) {
            responseHtml.append("<p>No users found with the specified resource.</p>");
        } else {
            responseHtml.append("<ul>");
            for (String user : users) {
                responseHtml.append("<li>").append(user).append("</li>");
            }
            responseHtml.append("</ul>");
        }

        // Return HTML content to be displayed on the same page
        return Response.ok(responseHtml.toString()).build();
    }
    
    

    @GET
    @Path("allusers")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAllUsers() {
        List<Map<String, String>> users = new ArrayList<>();

        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT username FROM users where user_type!='admin'";
            try (PreparedStatement stmt = conn.prepareStatement(query);
                 ResultSet rs = stmt.executeQuery()) {

                while (rs.next()) {
                    Map<String, String> user = new HashMap<>();
                    user.put("username", rs.getString("username"));
                    users.add(user);
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }

        return Response.ok(users).build();
    }


    @GET
    @Path("myteam")
    @Produces(MediaType.APPLICATION_JSON)
    public Response usersByManager(@Context HttpServletRequest request) {
        List<Map<String, String>> users = new ArrayList<>();
        HttpSession session = request.getSession();
        String m_username = (String) session.getAttribute("username");
        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT username FROM users WHERE managerID = ?";
            try (PreparedStatement stmt = conn.prepareStatement(query)) {
                // Set the managerID parameter in the query
                stmt.setString(1, m_username);
                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, String> user = new HashMap<>();
                        user.put("username", rs.getString("username"));
                        users.add(user);
                    }
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }

        return Response.ok(users).build();
    }

    
    

    @GET
    @Path("users")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUsers() {
        try (Connection conn = SampleDb.connect()) {
            String query = "SELECT firstname, lastname, username, managerID FROM users";
            try (PreparedStatement stmt = conn.prepareStatement(query);
                 ResultSet rs = stmt.executeQuery()) {

                List<User> users = new ArrayList<>();
                while (rs.next()) {
                    String firstname = rs.getString("firstname");
                    String lastname = rs.getString("lastname");
                    String username = rs.getString("username");
                    String managerID = rs.getString("managerID");
                    
                    User user = new User(firstname, lastname, username, managerID);
                    users.add(user);
                }
                
                return Response.ok(users.toString()).build();
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }
    }
    @POST
    @Path("addUser")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public void addUser(@FormParam("firstname") String firstname,
                         @FormParam("lastname") String lastname,
                         @FormParam("email") String email,
                         @Context HttpServletResponse response) throws IOException {
        
        try {
        	String password = firstname+lastname;
            User ob = new User(firstname, lastname, null, email, password,null);
            ob.registerUser();
            String username = ob.getUsername();
            response.sendRedirect("/uam/addUserSuccess.jsp?message=User Added successful&username=" + username);
        } catch (Exception e) {
            response.sendRedirect("/uam/userAddFailure.jsp?message=Failed To add User: " + e.getMessage());
        }
    }

    @POST
    @Path("changepassword")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response updatePassword(
            @FormParam("oldpassword") String oldpassword,
            @FormParam("newpassword") String newpassword, 
            @Context HttpServletRequest request) {
    	User u = new User();
        oldpassword=u.encrypt(oldpassword);
        newpassword=u.encrypt(newpassword);
        
        HttpSession session = request.getSession();
        String username = (String) session.getAttribute("username");
        
        try {
            Connection conn = SampleDb.connect();

            // First query: Check if the user exists and the old password matches
            String checkQuery = "SELECT COUNT(*) FROM users WHERE username = ? AND password = ?";
            PreparedStatement checkPassword = conn.prepareStatement(checkQuery);
            checkPassword.setString(1, username);
            checkPassword.setString(2, oldpassword);
            
            ResultSet resultSet = checkPassword.executeQuery();
            resultSet.next();
            int count = resultSet.getInt(1);

            if (count == 1) {
                // Second query: Update the password if the old password matches
                String updateQuery = "UPDATE users SET password = ? WHERE username = ?";
                PreparedStatement updatePassword = conn.prepareStatement(updateQuery);
                updatePassword.setString(1, newpassword);
                updatePassword.setString(2, username);
                updatePassword.executeUpdate();

                return Response.ok("Password changed successfully").build();
            } else {
                return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("Invalid old password or username").build();
            }
        } catch (Exception e) {
            e.printStackTrace();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("An error occurred while changing the password").build();
        }
    }

    @GET
    @Path("pass")
    
    	public String pas()
    	{
    		User u = new User();
    		return u.encrypt("vk");
    	}
    
    
    @POST
    @Path("updateuser")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response updateUser(
            @FormParam("username") String oldUsername,
            @FormParam("firstname") String firstname,
            @FormParam("lastname") String lastname) {

        Connection conn = null;
        PreparedStatement updateDetailsStmt = null;
        PreparedStatement updateUserResourcesStmt = null;
        PreparedStatement updateRequestsStmt = null;

        try {
            conn = SampleDb.connect();
            conn.setAutoCommit(false); // Start transaction

            // Generate a new username based on the updated firstname and lastname
            User user = new User(firstname, lastname, oldUsername);
            String newUsername = user.generateUsername();

            // Update the username, firstname, and lastname in the details table
            String updateDetailsQuery = "UPDATE users SET username = ?, firstname = ?, lastname = ? WHERE username = ?";
            updateDetailsStmt = conn.prepareStatement(updateDetailsQuery);
            updateDetailsStmt.setString(1, newUsername);
            updateDetailsStmt.setString(2, firstname);
            updateDetailsStmt.setString(3, lastname);
            updateDetailsStmt.setString(4, oldUsername);
            updateDetailsStmt.executeUpdate();

            // Update the username in the user_resources table
            String updateUserResourcesQuery = "UPDATE user_resources SET username = ? WHERE username = ?";
            updateUserResourcesStmt = conn.prepareStatement(updateUserResourcesQuery);
            updateUserResourcesStmt.setString(1, newUsername);
            updateUserResourcesStmt.setString(2, oldUsername);
            updateUserResourcesStmt.executeUpdate();

            // Update the username in the requests table
            String updateRequestsQuery = "UPDATE requests SET username = ? WHERE username = ?";
            updateRequestsStmt = conn.prepareStatement(updateRequestsQuery);
            updateRequestsStmt.setString(1, newUsername);
            updateRequestsStmt.setString(2, oldUsername);
            updateRequestsStmt.executeUpdate();

            // Commit the transaction
            conn.commit();

            return Response.ok("User updated successfully. New username: " + newUsername).build();
        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback(); // Rollback in case of error
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            return Response.serverError().entity("Failed to update user: " + e.getMessage()).build();
        } finally {
            // Close resources in the finally block to ensure they're always closed
            if (updateDetailsStmt != null) {
                try {
                    updateDetailsStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (updateUserResourcesStmt != null) {
                try {
                    updateUserResourcesStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (updateRequestsStmt != null) {
                try {
                    updateRequestsStmt.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
            if (conn != null) {
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    @POST
    @Path("addresource")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response addResource(@FormParam("resourceName") String resourceName) {
        String Query = "INSERT INTO resources (resource_name) VALUES (?)";

        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(Query)) {

            stmt.setString(1, resourceName);
            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                return Response.ok(resourceName+" added successfully.").build();
            } else {
                return Response.serverError().entity("Failed to add resource."+resourceName).build();
            }

        } catch (SQLException e) {
            return Response.serverError().entity(resourceName+" is already available!").build();
        }
    }

    @GET
    @Path("/showTeam")
    @Produces(MediaType.APPLICATION_JSON)
    public Response showTeam(@Context HttpServletRequest request) {
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
        
        List<Map<String, Object>> teamMembers = getTeamMembersByManagerID(managerID);
        return Response.ok(teamMembers).build();
    }

    private List<Map<String, Object>> getTeamMembersByManagerID(String managerID) {
        List<Map<String, Object>> teamMembers = new ArrayList<>();
        String query = "SELECT firstname, lastname, username, email FROM users WHERE managerID = ?";
        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, managerID);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> member = new HashMap<>();
                    member.put("firstname", rs.getString("firstname"));
                    member.put("lastname", rs.getString("lastname"));
                    member.put("username", rs.getString("username"));
                    member.put("email", rs.getString("email"));
                    teamMembers.add(member);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace(); // Consider better error handling here
        }
        return teamMembers;
    }
    
    @POST
    @Path("/removeUser")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response removeUser(@Context HttpServletRequest request,
                               @FormParam("username") String username) {
        try (Connection conn = SampleDb.connect()) {
            HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
            }
            
            String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
            if (managerID == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
            }
            String deleteQuery = "UPDATE users SET managerID = NULL WHERE username = ? AND managerID = ?";
            try (PreparedStatement stmt = conn.prepareStatement(deleteQuery)) {
                stmt.setString(1, username);
                stmt.setString(2, managerID);
                int rowsAffected = stmt.executeUpdate();

                if (rowsAffected > 0) {
                    return Response.ok(username+" removed from team successfully").build();
                } else {
                    return Response.status(Response.Status.NOT_FOUND).entity("User not found").build();
                }
            }
        } catch (SQLException e) {
            return Response.serverError().entity("Error removing user: " + e.getMessage()).build();
        }
    }



    @GET
    @Path("/getNullUsers")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getNullUsers(@Context HttpServletRequest request) {
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
        
        List<String> teamMembers = getAllNullUsers();
        return Response.ok(teamMembers).build();
    }
    
    private List<String> getAllNullUsers() {
        List<String> teamMembers = new ArrayList<>();
        String type = "user";
        String query = "SELECT username FROM users WHERE managerID IS NULL and user_type = ?";
        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, type);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    teamMembers.add(rs.getString("username"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace(); 
        }
        return teamMembers;
    }
    
    @POST
    @Path("/addToTeam")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response addToTeam(@FormParam("username") String username,@Context HttpServletRequest request) {
    	HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
        String updateQuery = "UPDATE users SET managerID = ? WHERE username = ?";

        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(updateQuery)) {

            stmt.setString(1, managerID);
            stmt.setString(2, username);
            int rowsAffected = stmt.executeUpdate();

            if (rowsAffected > 0) {
                return Response.ok(username+" added to "+managerID+"'s team successfully.").build();
            } else {
                return Response.serverError().entity("Failed to add user to team.").build();
            }

        } catch (SQLException e) {
            return Response.serverError().entity("Database error: " + e.getMessage()).build();
        }
    }
    
    
    @GET
    @Path("/getMyResources")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getMyResources(@Context HttpServletRequest request) {
        HttpSession session = request.getSession(false); // Use false to avoid creating a new session
        if (session == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
        }
        
        String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
        if (managerID == null) {
            return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
        }
        
        List<String> resources = getAllManagerResources(managerID);
        return Response.ok(resources).build();
    }

    private List<String> getAllManagerResources(String managerID) {
        List<String> resources = new ArrayList<>();
        
        // Update the query to fetch resources based on the managerID
        String query = "SELECT resource_name FROM user_resources WHERE username = ?";
        try (Connection conn = SampleDb.connect();
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, managerID);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    resources.add(rs.getString("resource_name")); // Fetch the correct column
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return resources;
    }
    
    
   

    @POST
    @Path("resourceRemove")
    @Consumes("application/x-www-form-urlencoded")
    public Response removeResourceFromManager(@Context HttpServletRequest request,
                                           @FormParam("resourceName") String resourceName) {
        try (Connection conn = SampleDb.connect()) {
        	HttpSession session = request.getSession(false); // Use false to avoid creating a new session
            if (session == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Session not found").build();
            }
            
            String managerID = (String) session.getAttribute("username"); // Ensure the session attribute name is correct
            if (managerID == null) {
                return Response.status(Response.Status.UNAUTHORIZED).entity("Manager ID not found").build();
            }
            String deleteQuery = "DELETE FROM user_resources WHERE username = ? AND resource_name = ?";
            try (PreparedStatement stmt = conn.prepareStatement(deleteQuery)) {
                stmt.setString(1, managerID);
                stmt.setString(2, resourceName);
                int rowsAffected = stmt.executeUpdate();

                if (rowsAffected > 0) {
                	return Response.ok(resourceName+" removed successfully").build();
                } else {
                	return Response.status(Response.Status.NOT_FOUND).entity("Resource or user not found").build();
                }
            }
        } catch (SQLException e) {
        	return Response.serverError().entity("Error removing resource: " + e.getMessage()).build();
        }
    }

}