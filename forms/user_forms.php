<?php
class user_forms{
    public function sign_up_form($ObjGlob){
?>
      <div class="row align-items-md-stretch">
        <div class="col-md-9">
          <div class="h-100 p-5 text-bg-dark rounded-3">
            <h2>Sign Up</h2>
            <?php
            print $ObjGlob->getMsg('msg');
            $err = $ObjGlob->getMsg('errors');
            ?>
            <form action="<?php print basename($_SERVER["PHP_SELF"]); ?>" method="POST" enctype="multipart/form-data">
                <div class="mb-3">
                    <label for="fullname" class="form-label">Fullname:</label>
					<input type="text" name="fullname" class="form-control form-control-lg" maxlength="50" id="fullname" placeholder="Enter your name" <?php print (isset($_SESSION["fullname"])) ? 'value="'.$_SESSION["fullname"].'"'  : ''; unset($_SESSION["fullname"]); ?> >
                    <?php print (isset($err['nameLetters_err'])) ? "<span class='invalid'>" . $err['nameLetters_err'] . "</span>" : '' ; ?>
                </div>
                <div class="mb-3">
                    <label for="email_address" class="form-label">Email Address:</label>
                    <input type="email" name="email_address" class="form-control form-control-lg" maxlength="50" id="email_address" placeholder="Enter your email address" <?php print (isset($_SESSION["email_address"])) ? 'value="'.$_SESSION["email_address"].'"'  : ''; unset($_SESSION["email_address"]); ?> >
                    <?php print (isset($err['email_format_err'])) ? "<span class='invalid'>" . $err['email_format_err'] . "</span>" : '' ; ?>
                    <?php print (isset($err['mailExists_err'])) ? "<span class='invalid'>" . $err['mailExists_err'] . "</span>" : '' ; ?>
                    <?php print (isset($err['mailDomain_err'])) ? "<span class='invalid'>" . $err['mailDomain_err'] . "</span>" : '' ; ?>
                </div>
                <div class="mb-3">
                    <label for="username" class="form-label">Username:</label>
                    <input type="text" name="username" class="form-control form-control-lg" maxlength="50" id="username" placeholder="Enter your username" <?php print (isset($_SESSION["username"])) ? 'value="'.$_SESSION["username"].'"'  : ''; unset($_SESSION["username"]); ?> >
                    <?php print (isset($err['usernameExists_err'])) ? "<span class='invalid'>" . $err['usernameExists_err'] . "</span>" : '' ; ?>
                    <?php print (isset($err['usernameLetters_err'])) ? "<span class='invalid'>" . $err['usernameLetters_err'] . "</span>" : '' ; ?>
                </div>
                <button type="submit" name="signup" class="btn btn-primary">Submit</button>
              </form>
          </div>
        </div>
<?php
    }    public function verify_code_form($ObjGlob){
?>
      <div class="row align-items-md-stretch">
        <div class="col-md-9">
          <div class="h-100 p-5 text-bg-dark rounded-3">
            <h2>Verify Code</h2>
            <?php
            print $ObjGlob->getMsg('msg');
            $err = $ObjGlob->getMsg('errors');
            ?>
            <form action="<?php print basename($_SERVER["PHP_SELF"]); ?>" method="POST" enctype="multipart/form-data">
                <div class="mb-3">
                    <label for="fullname" class="form-label">Verification Code:</label>
                    <input type="number" name="ver_code" class="form-control form-control-lg" maxlength="6" min="100000" max="999999" id="ver_code" placeholder="Enter your verification code" <?php print (isset($_SESSION["ver_code"])) ? 'value="'.$_SESSION["ver_code"].'"'  : ''; unset($_SESSION["ver_code"]); ?> >
                    <?php print (isset($err['not_numeric'])) ? "<span class='invalid'>" . $err['not_numeric'] . "</span>" : '' ; ?>
                    <?php print (isset($err['lenght_err'])) ? "<span class='invalid'>" . $err['lenght_err'] . "</span>" : '' ; ?>
                    <?php print (isset($err['ver_code_not_exist'])) ? "<span class='invalid'>" . $err['ver_code_not_exist'] . "</span>" : '' ; ?>
                    <?php print (isset($err['ver_code_expired'])) ? "<span class='invalid'>" . $err['ver_code_expired'] . "</span>" : '' ; ?>
                </div>
                <button type="submit" name="verify_code" class="btn btn-primary">Verify Code</button>
            </form>
          </div>
        </div>
<?php
    }   public function set_password_form($ObjGlob) {
      ?>
      <div class="row align-items-md-stretch">
          <div class="col-md-9">
              <div class="h-100 p-5 text-bg-dark rounded-3">
                  <h2>Set Password</h2>
                  <?php
                  print $ObjGlob->getMsg('msg'); // Display any messages
                  $err = $ObjGlob->getMsg('errors'); // Capture and display errors
                  ?>
                  <form action="<?php print basename($_SERVER["PHP_SELF"]); ?>" method="POST">
                      <div class="mb-3">
                          <label for="password" class="form-label">New Password:</label>
                          <input type="password" name="password" class="form-control form-control-lg" id="password" placeholder="Enter your new password">
                          <?php print (isset($err['password_err'])) ? "<span class='invalid'>" . $err['password_err'] . "</span>" : ''; ?>
                      </div>
                      <div class="mb-3">
                          <label for="confirm_password" class="form-label">Confirm Password:</label>
                          <input type="password" name="confirm_password" class="form-control form-control-lg" id="confirm_password" placeholder="Confirm your password">
                          <?php print (isset($err['confirm_password_err'])) ? "<span class='invalid'>" . $err['confirm_password_err'] . "</span>" : ''; ?>
                      </div>
                      <button type="submit" name="set_password" class="btn btn-primary">Set Password</button>
                  </form>
              </div>
          </div>
      </div>
      <?php
    }
}
