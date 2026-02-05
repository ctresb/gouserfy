package services

import (
	"context"

	"github.com/ctresb/gouserfy/database"
	"github.com/ctresb/gouserfy/models"
	"github.com/google/uuid"
)

type UserService struct {
	repo *database.UserRepository
}

func NewUserService(repo *database.UserRepository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *UserService) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.repo.GetByEmail(ctx, email)
}

func (s *UserService) GetByUsername(ctx context.Context, username string) (*models.User, error) {
	return s.repo.GetByUsername(ctx, username)
}

func (s *UserService) UpdateUsername(ctx context.Context, userID uuid.UUID, username string) error {
	return s.repo.UpdateUsername(ctx, userID, username)
}

func (s *UserService) UpdateStatus(ctx context.Context, userID uuid.UUID, status models.UserStatus) error {
	return s.repo.UpdateStatus(ctx, userID, status)
}

func (s *UserService) Delete(ctx context.Context, userID uuid.UUID) error {
	return s.repo.SoftDelete(ctx, userID)
}

func (s *UserService) GetProfile(ctx context.Context, userID uuid.UUID) (*models.UserProfile, error) {
	return s.repo.GetProfile(ctx, userID)
}

func (s *UserService) UpdateProfile(ctx context.Context, profile *models.UserProfile) error {
	return s.repo.UpdateProfile(ctx, profile)
}

func (s *UserService) GetPreferences(ctx context.Context, userID uuid.UUID) (*models.UserPreferences, error) {
	return s.repo.GetPreferences(ctx, userID)
}

func (s *UserService) UpdatePreferences(ctx context.Context, prefs *models.UserPreferences) error {
	return s.repo.UpdatePreferences(ctx, prefs)
}

func (s *UserService) GetVerification(ctx context.Context, userID uuid.UUID) (*models.UserVerification, error) {
	return s.repo.GetVerification(ctx, userID)
}

func (s *UserService) GetRoles(ctx context.Context, userID uuid.UUID) ([]models.Role, error) {
	return s.repo.GetUserRoles(ctx, userID)
}

func (s *UserService) AssignRole(ctx context.Context, userID uuid.UUID, roleName string, grantedBy *uuid.UUID) error {
	role, err := s.repo.GetRoleByName(ctx, roleName)
	if err != nil || role == nil {
		return err
	}
	return s.repo.AssignRole(ctx, userID, role.ID, grantedBy)
}

func (s *UserService) RemoveRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	role, err := s.repo.GetRoleByName(ctx, roleName)
	if err != nil || role == nil {
		return err
	}
	return s.repo.RemoveRole(ctx, userID, role.ID)
}

func (s *UserService) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	roles, err := s.repo.GetUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, r := range roles {
		if r.Name == roleName {
			return true, nil
		}
	}
	return false, nil
}
