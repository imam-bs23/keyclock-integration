import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import useAuth from "../hooks/useAuth";
import { login } from "../services/authService";

const Login = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { updateAuthState } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      console.log('Login attempt with username:', username);
      const loginResult = await login(username, password);
      console.log('Login successful:', loginResult);
      
      // Update auth state to reflect successful login
      const authState = await updateAuthState();
      console.log('Auth state after login:', authState);
      
      // Navigate to profile page
      console.log('Navigating to profile page');
      navigate("/profile");
    } catch (err) {
      console.error("Login error:", err);
      setError(
        err.error_description ||
          err.error ||
          "Failed to login. Please check your credentials."
      );
    } finally {
      setLoading(false);
    }
  };

  // Navigation to register page is now handled by Link component

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-6">
          <div className="card shadow-lg border-0">
            <div className="card-header bg-primary text-white py-3">
              <h4 className="mb-0 text-center d-flex align-items-center justify-content-center">
                <i className="bi bi-shield-lock me-2"></i>
                Login to Your Account
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
                <div className="mb-4">
                  <label htmlFor="username" className="form-label fw-bold">
                    <i className="bi bi-person me-1"></i> Username or Email
                  </label>
                  <div className="input-group">
                    <span className="input-group-text bg-light">
                      <i className="bi bi-person-fill text-primary"></i>
                    </span>
                    <input
                      type="text"
                      className="form-control py-2"
                      id="username"
                      placeholder="Enter your username or email"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      required
                      autoFocus
                    />
                  </div>
                </div>
                <div className="mb-4">
                  <label htmlFor="password" className="form-label fw-bold">
                    <i className="bi bi-key me-1"></i> Password
                  </label>
                  <div className="input-group">
                    <span className="input-group-text bg-light">
                      <i className="bi bi-lock-fill text-primary"></i>
                    </span>
                    <input
                      type="password"
                      className="form-control py-2"
                      id="password"
                      placeholder="Enter your password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                    />
                  </div>
                </div>
                <div className="d-grid gap-2 mt-4">
                  <button
                    type="submit"
                    className="btn btn-primary btn-lg py-2"
                    disabled={loading}
                  >
                    {loading ? (
                      <>
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                          aria-hidden="true"
                        ></span>
                        Logging in...
                      </>
                    ) : (
                      <>
                        <i className="bi bi-box-arrow-in-right me-2"></i>
                        Sign In
                      </>
                    )}
                  </button>
                </div>
              </form>
              <hr className="my-4" />
              <div className="text-center">
                <p className="mb-2">
                  Don't have an account?{" "}
                  <Link
                    to="/register"
                    className="text-primary fw-bold text-decoration-none"
                  >
                    <i className="bi bi-person-plus me-1"></i>
                    Register Now
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

export default Login;
