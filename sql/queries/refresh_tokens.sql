-- name: CreateRefreshToken :one
INSERT INTO
    refresh_tokens (
        token,
        created_at,
        updated_at,
        user_id,
        expires_at
    )
VALUES
    ($1, NOW(), NOW(), $2, $3)
RETURNING
    *;

-- name: GetUserForRefreshToken :one
SELECT
    user_id
FROM
    refresh_tokens
WHERE
    token = $1
    AND NOW() < expires_at
    AND revoked_at IS NULL;

-- name: RevokeRefreshToken :exec
UPDATE
    refresh_tokens
SET
    updated_at = NOW(),
    revoked_at = NOW()
WHERE
    token = $1
    AND NOW() < expires_at
    AND revoked_at IS NULL;
