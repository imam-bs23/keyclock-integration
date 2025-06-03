import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { registerUser } from "../services/authService";

const Register = () => {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    firstName: "",
    lastName: "",
    password: "",
    confirmPassword: ""
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const validateForm = () => {
    // Reset previous errors
    setError("");
    
    // Check for empty required fields
    if (!formData.username || !formData.email || !formData.password || !formData.confirmPassword) {
      setError("All required fields must be filled");
      return false;
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      setError("Please enter a valid email address");
      return false;
    }
    
    // Check password length
    if (formData.password.length < 8) {
      setError("Password must be at least 8 characters long");
      return false;
    }
    
    // Check if passwords match
    if (formData.password !== formData.confirmPassword) {
      setError("Passwords do not match");
      return false;
    }
    
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setLoading(true);
    setError("");
    
    try {
      // Call the registration API
      await registerUser({
        username: formData.username,
        email: formData.email,
        firstName: formData.firstName || formData.username,
        lastName: formData.lastName || "",
        password: formData.password
      });
      
      // Show success message
      setSuccess(true);
      
      // Redirect to login page after a delay
      setTimeout(() => {
        navigate("/login");
      }, 3000);
    } catch (err) {
      console.error("Registration error:", err);
      if (err.error === "username_exists") {
        setError("Username already exists. Please choose another username.");
      } else if (err.error === "email_exists") {
        setError("Email already in use. Please use another email address.");
      } else if (err.error_description) {
        setError(err.error_description);
      } else {
        setError("Registration failed. Please try again later.");
      }
    } finally {
      setLoading(false);
    }
  };

  if (success) {
    return (
      <div className="container mt-5">
        <div className="row justify-content-center">
          <div className="col-md-6">
            <div className="card shadow-lg border-0">
              <div className="card-body p-5 text-center">
                <div className="mb-4">
                  <i className="bi bi-check-circle-fill text-success" style={{ fontSize: '4rem' }}></i>
                </div>
                <h2 className="card-title mb-3">Registration Successful!</h2>
                <p className="card-text mb-4">
                  Your account has been created successfully. You will be redirected to the login page shortly.
                </p>
                <div className="d-flex align-items-center justify-content-center mb-4">
                  <p className="mb-0 me-3">Redirecting to login page</p>
                  <div className="spinner-border spinner-border-sm text-success" role="status">
                    <span className="visually-hidden">Loading...</span>
                  </div>
                </div>
                <div className="d-grid gap-2">
                  <Link to="/login" className="btn btn-primary">
                    <i className="bi bi-box-arrow-in-right me-2"></i>
                    Go to Login Now
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-6">
          <div className="card shadow-lg border-0">
            <div className="card-header bg-success text-white py-3">
              <h4 className="mb-0 text-center d-flex align-items-center justify-content-center">
                <i className="bi bi-person-plus me-2"></i>
                Register New Account
              </h4>
            </div>
            <div className="card-body p-4">
              {error && (
                <div className="alert alert-danger d-flex align-items-center" role="alert">
                  <i className="bi bi-exclamation-triangle-fill me-2"></i>
                  <div>{error}</div>
                </div>
              )}
              
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="username" className="form-label fw-bold">
                    <i className="bi bi-person me-1"></i> Username <span className="text-danger">*</span>
                  </label>
                  <div className="input-group">
                    <span className="input-group-text bg-light">
                      <i className="bi bi-person-fill text-success"></i>
                    </span>
                    <input
                      type="text"
                      className="form-control py-2"
                      id="username"
                      name="username"
                      placeholder="Choose a username"
                      value={formData.username}
                      onChange={handleChange}
                      required
                      autoFocus
                    />
                  </div>
                </div>
                
                <div className="mb-3">
                  <label htmlFor="email" className="form-label fw-bold">
                    <i className="bi bi-envelope me-1"></i> Email <span className="text-danger">*</span>
                  </label>
                  <div className="input-group">
                    <span className="input-group-text bg-light">
                      <i className="bi bi-envelope-fill text-success"></i>
                    </span>
                    <input
                      type="email"
                      className="form-control py-2"
                      id="email"
                      name="email"
                      placeholder="Enter your email address"
                      value={formData.email}
                      onChange={handleChange}
                      required
                    />
                  </div>
                </div>
                
                <div className="row mb-3">
                  <div className="col-md-6">
                    <label htmlFor="firstName" className="form-label fw-bold">
                      <i className="bi bi-person-badge me-1"></i> First Name
                    </label>
                    <input
                      type="text"
                      className="form-control py-2"
                      id="firstName"
                      name="firstName"
                      placeholder="First name"
                      value={formData.firstName}
                      onChange={handleChange}
                    />
                  </div>
                  <div className="col-md-6">
                    <label htmlFor="lastName" className="form-label fw-bold">
                      <i className="bi bi-person-badge me-1"></i> Last Name
                    </label>
                    <input
                      type="text"
                      className="form-control py-2"
                      id="lastName"
                      name="lastName"
                      placeholder="Last name"
                      value={formData.lastName}
                      onChange={handleChange}
                    />
                  </div>
                </div>
                
                <div className="mb-3">
                  <label htmlFor="password" className="form-label fw-bold">
                    <i className="bi bi-key me-1"></i> Password <span className="text-danger">*</span>
                  </label>
                  <div className="input-group">
                    <span className="input-group-text bg-light">
                      <i className="bi bi-lock-fill text-success"></i>
                    </span>
                    <input
                      type="password"
                      className="form-control py-2"
                      id="password"
                      name="password"
                      placeholder="Create a password (min. 8 characters)"
                      value={formData.password}
                      onChange={handleChange}
                      required
                    />
                  </div>
                  <div className="form-text">Password must be at least 8 characters long</div>
                </div>
                
                <div className="mb-4">
                  <label htmlFor="confirmPassword" className="form-label fw-bold">
                    <i className="bi bi-key-fill me-1"></i> Confirm Password <span className="text-danger">*</span>
                  </label>
                  <div className="input-group">
                    <span className="input-group-text bg-light">
                      <i className="bi bi-lock-fill text-success"></i>
                    </span>
                    <input
                      type="password"
                      className="form-control py-2"
                      id="confirmPassword"
                      name="confirmPassword"
                      placeholder="Confirm your password"
                      value={formData.confirmPassword}
                      onChange={handleChange}
                      required
                    />
                  </div>
                </div>
                
                <div className="d-grid gap-2 mt-4">
                  <button
                    type="submit"
                    className="btn btn-success btn-lg py-2"
                    disabled={loading}
                  >
                    {loading ? (
                      <>
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                          aria-hidden="true"
                        ></span>
                        Registering...
                      </>
                    ) : (
                      <>
                        <i className="bi bi-person-plus me-2"></i>
                        Create Account
                      </>
                    )}
                  </button>
                </div>
              </form>
              
              <hr className="my-4" />
              <div className="text-center">
                <p className="mb-2">
                  Already have an account?{" "}
                  <Link
                    to="/login"
                    className="text-primary fw-bold text-decoration-none"
                  >
                    <i className="bi bi-box-arrow-in-right me-1"></i>
                    Login Now
                  </Link>
                </p>
                <Link
                  to="/"
                  className="btn btn-outline-secondary mt-2"
                >
                  <i className="bi bi-house-door me-1"></i>
                  Back to Home
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
