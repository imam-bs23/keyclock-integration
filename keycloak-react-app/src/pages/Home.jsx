import { Link } from "react-router-dom";
import useAuth from "../hooks/useAuth";
import { logout } from "../services/authService";

const Home = () => {
  const { authenticated, loading } = useAuth();

  const handleLogout = async (e) => {
    e.preventDefault();
    try {
      await logout();
      // The page will refresh after logout
    } catch (err) {
      console.error("Logout error:", err);
    }
  };

  if (loading) {
    return (
      <div className="container mt-5 text-center">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
        <p className="mt-3">Initializing authentication...</p>
      </div>
    );
  }

  return (
    <div className="container mt-5">
      <div className="card shadow-lg border-0">
        <div className="card-body p-5">
          <div className="text-center mb-4">
            <i className="bi bi-shield-lock text-primary" style={{ fontSize: '3rem' }}></i>
            <h1 className="display-4 mt-3">Welcome to Keycloak Auth App</h1>
            <p className="lead">
              This is a simple application demonstrating Keycloak authentication
              with React and a secure backend proxy.
            </p>
          </div>
          <hr className="my-4" />

          {authenticated ? (
            <div className="text-center">
              <div className="alert alert-success d-flex align-items-center" role="alert">
                <i className="bi bi-check-circle-fill me-2"></i>
                <div>
                  <h4 className="alert-heading">Successfully Logged In!</h4>
                  <p className="mb-0">You are now authenticated with Keycloak.</p>
                </div>
              </div>
              <div className="mt-4 d-flex justify-content-center gap-3">
                <Link 
                  to="/profile" 
                  className="btn btn-primary btn-lg"
                >
                  <i className="bi bi-person-circle me-2"></i>
                  View Profile
                </Link>
                <button 
                  className="btn btn-danger btn-lg" 
                  onClick={handleLogout}
                >
                  <i className="bi bi-box-arrow-right me-2"></i>
                  Logout
                </button>
              </div>
            </div>
          ) : (
            <div className="text-center">
              <p>Please login or create a new account to get started.</p>
              <div className="d-flex justify-content-center gap-3 mt-4">
                <Link to="/login" className="btn btn-primary btn-lg">
                  <i className="bi bi-box-arrow-in-right me-2"></i>
                  Login
                </Link>
                <Link to="/register" className="btn btn-success btn-lg">
                  <i className="bi bi-person-plus me-2"></i>
                  Register
                </Link>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Home;
