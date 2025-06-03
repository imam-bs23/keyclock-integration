import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Container, Alert, Spinner } from "react-bootstrap";
import axios from "axios";

const Callback = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleCallback = async () => {
      try {
        // Get query parameters from URL
        const params = new URLSearchParams(location.search);
        
        // Check for errors in the callback
        if (params.get("error")) {
          setError(`${params.get("error")}: ${params.get("error_description") || "Unknown error"}`);
          setLoading(false);
          return;
        }

        // Process the callback with our backend
        const response = await axios.get(
          `http://localhost:3001/api/auth/callback${location.search}`,
          { withCredentials: true }
        );

        if (response.data.success) {
          // If we have a token, store it (your auth service should handle this)
          if (response.data.token) {
            // This would typically be handled by your auth service
            console.log("Authentication successful");
            
            // Redirect to the specified page or home
            setTimeout(() => {
              navigate(response.data.redirect || "/");
            }, 1000);
          } else {
            // If no token but success, just redirect
            setTimeout(() => {
              navigate(response.data.redirect || "/");
            }, 1000);
          }
        } else {
          setError(response.data.error_description || "Authentication failed");
        }
      } catch (err) {
        console.error("Callback processing error:", err);
        setError("Failed to process authentication callback");
      } finally {
        setLoading(false);
      }
    };

    handleCallback();
  }, [location, navigate]);

  return (
    <Container className="mt-5 text-center">
      <h2>Processing Authentication</h2>
      
      {loading ? (
        <div className="mt-4">
          <Spinner animation="border" role="status">
            <span className="visually-hidden">Loading...</span>
          </Spinner>
          <p className="mt-3">Please wait while we complete your authentication...</p>
        </div>
      ) : error ? (
        <Alert variant="danger" className="mt-4">
          <Alert.Heading>Authentication Error</Alert.Heading>
          <p>{error}</p>
          <div className="d-flex justify-content-end">
            <button 
              className="btn btn-outline-danger" 
              onClick={() => navigate("/login")}
            >
              Return to Login
            </button>
          </div>
        </Alert>
      ) : (
        <Alert variant="success" className="mt-4">
          <Alert.Heading>Authentication Successful</Alert.Heading>
          <p>You are being redirected to the application...</p>
        </Alert>
      )}
    </Container>
  );
};

export default Callback;
