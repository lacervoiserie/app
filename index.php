<?php echo $_GET [ 'token' ]; ?> 

<html>
 <body>
  PAGE
  <form method="post" action="http://localhost:3000/api/reset_password">
    <input type="text" name="newPassword">
    <input type="submit" value="post">
  </form>
 </body>
</html>