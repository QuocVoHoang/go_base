package usecase

import (
	"context"
	"fmt"
	"strings"

	"github.com/your-org/go-base/internal/domain/entity"
	"github.com/your-org/go-base/internal/domain/repository"
	"github.com/your-org/go-base/internal/domain/usecase/dto"
	"github.com/your-org/go-base/pkg/http_error"
	middlewarepkg "github.com/your-org/go-base/pkg/middleware"
)

type registerUsecase struct {
	userRepo  repository.IUserRepo
	txManager repository.TransactionManager
	jwt       middlewarepkg.JWT
}

func NewRegisterUsecase(
	userRepo repository.IUserRepo,
	txManager repository.TransactionManager,
	jwt middlewarepkg.JWT,
) RegisterUsecase {
	return &registerUsecase{
		userRepo:  userRepo,
		txManager: txManager,
		jwt:       jwt,
	}
}

func (uc *registerUsecase) Do(ctx context.Context, req dto.RegisterRequest) (*dto.RegisterResult, error) {
	if err := validateRegisterRequest(req); err != nil {
		return nil, err
	}

	var result *dto.RegisterResult
	err := uc.txManager.WithinTransaction(ctx, func(ctx context.Context) error {
		normalizedEmail := normalizeEmail(req.Email)
		existingUser, err := uc.userRepo.FindByEmail(ctx, normalizedEmail)
		if err == nil && existingUser != nil {
			return http_error.ConflictError("email already exists")
		}
		if err != nil {
			return err
		}

		salt, err := generateSalt()
		if err != nil {
			return fmt.Errorf("generate password salt: %w", err)
		}

		hashedPassword, err := hashPassword(req.Password, salt)
		if err != nil {
			return fmt.Errorf("hash password: %w", err)
		}

		birthdate, err := parseOptionalDate(req.Birthdate)
		if err != nil {
			return http_error.BadRequestError("birthdate must use YYYY-MM-DD format")
		}

		user := &entity.User{
			Email:        normalizedEmail,
			Phone:        normalizeOptional(req.Phone),
			FullName:     normalizeRequired(req.FullName),
			Role:         req.Role,
			Status:       entity.UserStatusActive,
			Password:     hashedPassword,
			PasswordSalt: salt,
			Avatar:       req.Avatar,
			Birthdate:    birthdate,
		}
		if err := uc.userRepo.Create(ctx, user); err != nil {
			return fmt.Errorf("create user: %w", err)
		}

		userResult := buildUserResult(*user)
		result = &userResult
		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

func validateRegisterRequest(req dto.RegisterRequest) error {
	email := normalizeEmail(req.Email)
	if email == "" {
		return http_error.BadRequestError("email is required")
	}
	if !validEmail(email) {
		return http_error.BadRequestError("email is invalid")
	}
	if strings.TrimSpace(req.Password) == "" {
		return http_error.BadRequestError("password is required")
	}
	if normalizeRequired(req.FullName) == "" {
		return http_error.BadRequestError("full_name is required")
	}
	if !validRole(req.Role) {
		return http_error.BadRequestError("role must be 1, 2, or 3")
	}
	return nil
}
