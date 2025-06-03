import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import useAuth from "../hooks/useAuth";
import { logout } from "../services/authService";

const Profile = () => {
  const { authenticated, userProfile, loading, error, fetchUserProfile } =
    useAuth();
  const [isLoading, setIsLoading] = useState(false);
  const [profileError, setProfileError] = useState(null);
  const navigate = useNavigate();

  // Redirect to home if not authenticated
  useEffect(() => {
    if (!loading && !authenticated) {
      navigate("/login");
    }
  }, [authenticated, loading, navigate]);

  // Fetch user profile when component mounts
  useEffect(() => {
    const loadProfile = async () => {
      console.log("Profile component - Auth state:", {
        authenticated,
        userProfile,
      });
      if (authenticated) {
        setIsLoading(true);
        try {
          console.log("Fetching user profile...");
          const profile = await fetchUserProfile();
          console.log("Profile fetched successfully:", profile);
        } catch (err) {
          console.error("Failed to load profile:", err);
          setProfileError(
            err.error_description || "Failed to load user profile"
          );
        } finally {
          setIsLoading(false);
        }
      } else if (!loading) {
        console.log("Not authenticated, redirecting to login");
        navigate("/login");
      }
    };

    loadProfile();
  }, []);

  const handleLogout = async (e) => {
    e.preventDefault();
    await logout();
  };

  if (loading || isLoading) {
    return (
      <div className="container mt-5 text-center">
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
        <p className="mt-3">Loading profile...</p>
      </div>
    );
  }

  if (profileError || error) {
    return (
      <div className="container mt-5">
        <div className="alert alert-danger" role="alert">
          <h4 className="alert-heading">Error Loading Profile</h4>
          <p>{profileError || error}</p>
          <hr />
          <p className="mb-0">
            <button
              className="btn btn-outline-danger"
              onClick={() => navigate("/login")}
            >
              Back to Login
            </button>
          </p>
        </div>
      </div>
    );
  }

  if (!authenticated) {
    return null; // Will redirect in useEffect
  }

  return (
    <div className="container mt-4">
      <div className="row justify-content-center">
        <div className="col-md-8">
          <div className="card shadow">
            <div className="card-header bg-primary text-white">
              <h4 className="mb-0">User Profile</h4>
            </div>
            <div className="card-body">
              <div className="alert alert-success">
                <p className="mb-0">You are successfully authenticated!</p>
                <small className="text-muted">
                  {userProfile?.sub?.startsWith("kc_")
                    ? "Using Keycloak Authentication"
                    : "Using Simple JWT Authentication"}
                </small>
              </div>

              <h5 className="mt-4">User Information</h5>
              <div className="table-responsive">
                <table className="table table-bordered">
                  <tbody>
                    <tr>
                      <th>Username</th>
                      <td>{userProfile?.username}</td>
                    </tr>
                    <tr>
                      <th>Full Name</th>
                      <td>
                        {userProfile?.first_name || userProfile?.last_name
                          ? `${userProfile?.first_name || ""} ${
                              userProfile?.last_name || ""
                            }`.trim()
                          : "Not provided"}
                      </td>
                    </tr>
                    <tr>
                      <th>Email</th>
                      <td>{userProfile?.email || "Not provided"}</td>
                    </tr>
                    <tr>
                      <th>User ID</th>
                      <td>{userProfile?.sub || "Not available"}</td>
                    </tr>
                    <tr>
                      <th>Roles</th>
                      <td>
                        {userProfile?.roles && userProfile.roles.length > 0
                          ? userProfile.roles.join(", ")
                          : "No roles assigned"}
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div className="d-grid gap-2 mt-4">
                <Link to="/" className="btn btn-primary">
                  <i className="bi bi-house-door me-2"></i>
                  Back to Home
                </Link>
                <button onClick={handleLogout} className="btn btn-danger">
                  <i className="bi bi-box-arrow-right me-2"></i>
                  Logout
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;
