<?php
/**
 * Plugin Name:     WP Magic Links
 * Plugin URI:      https://timnash.co.uk
 * Description:     Simple Passwordless Login
 * Author:          Tim Nash
 * Author URI:      https://timnash.co.uk
 * Version:         0.1.0
 *
 */

/*
 * Plugin Actions & Filters
 *
 */
// Check for password link on login, note lower prioty to avoid conflicts
add_action( 'init', 'wpmagiclinks_login_with_token', 5 );

// Allows the function to be called, by the single event cron
add_action( 'magiclinks_token_cleanup', 'wpmagiclinks_expire_token', 10, 2 );

// Add Shortcode for Magic Link
add_shortcode('magiclink_login', 'wpmagiclinks_generate_shortcode');

 /**
  * Login with Token
  * Main login logic, checks for the token on the login page and checks if valid
  *
  */
 function wpmagiclinks_login_with_token(){

	 //Catch our errors
	 $errors = new WP_Error();

	 //Check if we are on the login page, and that the token is present
	 global $pagenow;
	 if( 'wp-login.php' !== $pagenow || empty( $_GET['login_with_token'] ) ){
		 return false;
	 }

	 // Check if the user is logged in, if they are then ignore this request, and let WP handle it.
	 if( is_user_logged_in() ){
		 return false;
	 }

	 /* Check Crons are expired
	  * Thanks to Daniel Bachhuber for inspiration and code
	  * https://wordpress.org/plugins/one-time-login/
	  */

	 //Get crons this uses the undocumented internal array
	 $crons = _get_cron_array();
	 if( ! empty( $crons ) ){
		 foreach( $crons as $time => $hooks ){

			 // If the time of the hook is in the future jump to next one
			 if( time() < $time ){
				 continue;
			 }

			 //Anything else we have here should have been processed
			 foreach ($hooks as $hook => $events) {

				 // If it's not our cron job carry on looping
				 if( 'magiclinks_token_cleanup' !== $hook ){
					 continue;
				 }
				 foreach( $events as $sig => $data){

					 //Ok let's pretend to be the cron
					if( ! defined( 'DOING_CRON' ) ){
						define( 'DOING_CRON', true );
					}

					//Run the cron events
					do_action_ref_array( $hook, $data['args'] );

					//Remove the event now we have ran it
					wp_unschedule_event( $time, $hook, $data['args'] );
				 }
			 }
		 }
	 }

	 // Get our payload and un-encode the base64 to our serialised string
	 $login_with_token = $_GET['login_with_token'];
	 $login_with_token = base64_decode( $login_with_token, true );

	 //If our Base64 appears to have been manipulated
	 if( ! $login_with_token ){
		$errors->add(
			'magiclink_login',
				__( 'Base64 Error, object has been manipulated', 'magiclink')
		);
		wpmagiclinks_login_error( $errors );
	 }

	 $login_with_token = json_decode( $login_with_token, true );

	 // If we don't have an array or it is empty or its missing our data
	 if( ! is_array( $login_with_token ) || ! $login_with_token['id'] || ! $login_with_token['token']){
		$errors->add(
			'magiclink_login',
				__( 'Token or user ID data is missing', 'magiclink')
		);
		wpmagiclinks_login_error( $errors );
	 }

	 // Lets check if the user is a valid user
	 $user_id = (int) $login_with_token['id'];
	 $user = get_user_by( 'id', $user_id );
	 if( ! $user ){
		$errors->add(
			'magiclink_login',
				__( 'Failed to get user by ID', 'magiclink')
		);
		wpmagiclinks_login_error( $errors );
	 }

	 // Get the user tokens from the database for the user
	 $tokens = get_user_meta( $user->ID, 'magiclink_tokens', true );

	 // Get the token from our payload
	 $payload_token = (string) $login_with_token['token'];

	 // Loops our tokens and compare the hashes
	 foreach( $tokens as $key => $token){
		 if( hash_equals( $token, $payload_token ) ){

			// remove the token, as its now been used
			 unset($tokens[ $key ] );
			 update_user_meta( $user->ID, 'magiclink_tokens', $tokens );
			 wp_set_auth_cookie( $user->ID, true, is_ssl() );

			// Do all the usual user login
			do_action( 'wp_login', $user->user_login, $user );

			// redirect the user
			$redirect = apply_filters( 'magiclink_redirect_url', admin_url() );
			wp_safe_redirect( $redirect );
			exit;
		 }
	 }
	$errors->add(
		'magiclink_login',
			__( 'Token could not be found, it either expired or is not valid', 'magiclink')
	);
	wpmagiclinks_login_error( $errors );
 }

 /*
  * Login Error Helper
  * Provide some information when debugging but disabled when in production
  */
function wpmagiclinks_login_error( object $error ){

	// If WP_DEBUG is set show more detailed errors
	 if( defined( 'WP_DEBUG') && true === WP_DEBUG ){

		//Check if our error object is valid
		if( is_wp_error( $error ) ){

			//Display Error details
			wp_die( $error->get_error_message(),  $error->get_error_code() );
		}
	 }

	 //Display generic error, in production
	 wp_die('This link token is invalid');
 }


 /*
  * Generate Token
  * Generates the Token and stores it in the usermeta table
  */
 function wpmagiclinks_generate_token( int $id ){
	 //Get current list of tokens for this user
	$tokens = get_user_meta( $id, 'magiclink_tokens', true );

	//If the return is not an array, create a blank array
	if( !is_array($tokens) || empty( $tokens ) ){
		$tokens = array();
	}

	//Use the Generate password option, and then hash it for storage in the DB
	$token = hash( 'sha256', wp_generate_password() );

	//Add our new generated token, to the existing list and update it.
	$tokens[] = $token;
	update_user_meta( $id, 'magiclink_tokens', $tokens );

	//Set the time before we expire the token
	$expire = time() + ( 10 * MINUTE_IN_SECONDS );

	//Time can be changed by the filter
	$expire = apply_filters( 'magiclinks_expiry_time', $expire );

	//Schedule a cron job to clean up
	wp_schedule_single_event( $expire, 'magiclinks_token_cleanup', array( $id, $token ));

	//Return the token so we can inform the user of it
	return $token;
 }

 /*
  * Generate Link
  * Generates a Link which can be passed to the user to authenticate against
  */
 function wpmagiclinks_generate_link( int $id, string $token ){
	//Generate our array and JSON Encode it
	$payload = array(
		'id' 	=> $id,
		'token' => $token
	);
	$payload = json_encode( $payload );

	// Get the login location and append our payload token
	$login_url = site_url( 'wp-login.php', 'login' );
	$login_url = add_query_arg( 'login_with_token', urlencode($payload), $login_url );

	//apply any additional filters (for example if someone has moved the login location)
	return apply_filters( 'login_url', $login_url, '', false );
 }

 /*
  * Expire Token
  * Expire the token if its still in list
  */
 function wpmagiclinks_expire_token( int $id, string $expired_token ){
	// Get the list of active tokens for the user if there are none, bail out.
	$tokens = get_user_meta( $id, 'magiclink_tokens', true );
	if( !is_array( $tokens) ){
		return false;
	}
	//Loop through tokens, looking for our token.
	foreach( $tokens as $key => $token ){
		if( $expired_token === $token){
			unset($tokens[$key]);
		}
	}

	// Return the new token now minus our expired token back to the database.
	return update_user_meta( $id, 'magiclink_tokens', $tokens );
 }

 /*
  * Send Email
  * Send a configurable email with the login link
  */
 function wpmagiclinks_send_email( object $user, string $token ){
	 $errors = new WP_Error();
	 // Get the users Email
	$user_email = $user->user_email;

	//Set the email subject, can be changed by filter
	$subject = _('Login Link', 'magiclink');
	$subject = apply_filters( 'magiclink_email_subject', $subject);

	//Generate the URL for the login link
	$url = wpmagiclinks_generate_link( $user->ID, $token );

	// Something has gone wrong
	if( ! $url ){
		$errors->add(
			'send_magiclink_email',
			__( 'The Link URL could not be generated', 'magiclink')
		);
		return $errors;
	}

	// Depending if it's multisite or not, get the site name
	if( is_multisite() ){
		$site_name = get_network()->site_name;
	}else{
		$site_name = wp_specialchars_decode( get_option( 'blogname' ), ENT_QUOTES );
	}

	// Generate messsage, provide opportunity to filer
	$message = sprintf( __( 'To login to %s', 'magiclink' ), $site_name ) . "\r\n\r\n";
	$message .= __( 'please visit the following address:' , 'magiclink') . "\r\n\r\n";
	$message .= $url. "\r\n\r\n";
	$message .= __( 'This link will expire after 10 minutes' , 'magiclink') . "\r\n\r\n";
	$message = apply_filters( 'magiclink_email_message', $message );

	// Send email with login link
	if( $message && ! wp_mail( $user_email, wp_specialchars_decode( $subject ), $message ) ){
		$errors->add(
			'send_magiclink_email',
				__( 'The email could not be sent. Your site may not be correctly configured to send emails', 'magiclink')
		);
		return $errors;
	}
	return true;
 }

 /*
  * Generate Form
  * Generate the skeleton HTML of the form
  * Content Filterable to change the form look and feel
  */
 function wpmagiclinks_generate_form(){
	 ob_start();
	?>
	<form method="post" action="" id="wpmagiclinks_form">
	<label><?php _e('Username', 'magiclinks' ) ?></label>
	<?php wp_nonce_field('wpmagiclinks_form'); ?>
	<input type="email" id="wpmagiclinks_form_email" name="wpmagiclinks_form_email" >
	<input type="submit" id="wpmagiclinks_form_submit" name="wpmagiclinks_form_submit" value="send" >
	</form>
	<?php
	$form = ob_get_contents();
	ob_get_clean();
	return apply_filters( 'magiclink_form', $form );
 }

 /*
  * Generate the Shortcode for login
  * Add a shortcode to allow users to request a link
  */
 function wpmagiclinks_generate_shortcode(){
	 // Set WP error object to handle validation
	 $errors = new WP_Error();

	 //Define Message if we are going to show one
	 $message = false;

	 //Toggle show form
	 $show_form = true;

	 //Check if user is logged in, add message do not show form
	 if( is_user_logged_in() ){
		$errors->add(
			'wpmagiclink_shortcode',
				__( 'You are already logged in', 'magiclink')
		);
		$show_form = false;
	 }else{

		// Verify the Nonce and reject if not valid, allow reattempts
		 if( ! wp_verify_nonce( $_POST['_wpnonce'], "wpmagiclinks_form" ) ){
			$errors->add(
				'wpmagiclink_shortcode',
					__( 'There was an error please try again', 'magiclink')
			);
		 }else{

			// Verify email has content
			if( empty( $_POST['wpmagiclinks_form_email'] ) ){
				$errors->add(
					'wpmagiclink_shortcode',
						__( 'Email is missing', 'magiclink')
				);
			}else{

				//Check the email is a valid email format
				if( ! filter_var( $_POST['wpmagiclinks_form_email'], FILTER_VALIDATE_EMAIL ) ){
					$errors->add(
						'wpmagiclink_shortcode',
							__( 'Invalid Email Format', 'magiclink')
					);
				}else{

					//Attempt to get the user by the email address
					$user = get_user_by( "email", $_POST['wpmagiclinks_form_email'] );

					//If not valid dont throw error to avoid identifying emails
					if( $user ){

						//Generate the user token for the user
						$token = wpmagiclinks_generate_token( $user->ID );
						if( ! $token ){
							$errors->add(
								'wpmagiclink_shortcode',
									__( 'Error Please check Details and try again', 'magiclink')
							);
						}else{

							//Send the email
							$email = wpmagiclinks_send_email( $user, $token );

							//If the email comes back with errors, pass them to this instance of the WP_Error object
							if( is_wp_error( $email ) ){
								$errors->add(
									'wpmagiclink_shortcode',
									$email->get_error_message()
								);
						}
					}
				}
			}
		 }
	 }
	}
	 //Set the message, either it will be an error message, or generic success message
	 if( is_wp_error( $errors ) ){

		// Add message to form
		$message = $errors->get_error_message();

		//Add html class to make styling easier
		$class = 'wpmagiclinks_error';
	 }else{

		// Add Success Message
		$message = __( 'If email was valid, email will be sent sent, check your inbox', 'magiclink' );

		// Add html class to make styling easier
		$class = 'wpmagiclinks_success';

		//Don't show the Form as we have sent the email
		$show_form = false;
	 }

	 // Filters to change the message being sent, and to add/modify classes to the message form
	 $message = apply_filters('wpmagiclink_form_sent_message', $message );
	 $class = apply_filters( 'wpmagiclink_form_sent_message_class', $message, $class );
	 //Ok let's create the form and bits
	 ?>
	 <div id="wpmagiclinks">
	 <?php
	 // Show message if we have already processed the form
	 if( $message ){
	?>
		<div id="wpmagiclinks_message" class="<?php echo $class ?>">
		<?php echo $message; ?>
		</div>
	<?php
	 }
	 // Show form if it has yet to be processed or error needs correcting
	 if( $show_form ){
		echo wpmagiclinks_generate_form();
	 }
	 ?>
	 </div>
	 <?php
}
