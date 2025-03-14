package controller

import (
	"Glue-API/httputil"
	"Glue-API/utils"
	"Glue-API/utils/license"
	"net/http"

	"github.com/gin-gonic/gin"
)

// License godoc
//
//	@Summary		Show License
//	@Description	라이센스를 조회합니다.
//	@Tags			License
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	LicenseList
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/license [get]
func (c *Controller) License(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")

	license_data, err := license.License()
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.IndentedJSON(http.StatusOK, license_data)
}

// IsLicenseExpired godoc
//
//	@Summary                IsLicenseExpired
//	@Description    		라이센스 만료일을 조회합니다.
//	@Tags                   License
//	@Accept                 x-www-form-urlencoded
//	@Produce                json
//	@Success                200     {object}        LicenseList
//	@Failure                400     {object}        httputil.HTTP400BadRequest
//	@Failure                404     {object}        httputil.HTTP404NotFound
//	@Failure                500     {object}        httputil.HTTP500InternalServerError
//	@Router                 /api/v1/license/isLicenseExpired [get]
func (c *Controller) IsLicenseExpired(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")

	expirationDate, err := license.GetExpirationDate("password", "salt")
	if err != nil {
		// 에러 발생 시 만료된 것으로 간주하고 에이전트 중지
		license.ControlHostAgent(false) // agent 중지
		ctx.JSON(http.StatusOK, gin.H{
			"expired":     true,
			"expiry_date": "",
			"error":       err.Error(),
		})
		return
	}

	expired, err := license.IsLicenseExpired("password", "salt")
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	// 만료 여부에 따라 에이전트 제어
	if expired {
		license.ControlHostAgent(false) // 만료되었으면 agent 중지
	} else {
		license.ControlHostAgent(true) // 유효하면 agent 시작
	}

	ctx.JSON(http.StatusOK, gin.H{
		"expired":     expired,
		"expiry_date": expirationDate,
	})
}

// ControlHostAgent godoc
//
//	     @Summary                ControlHostAgent
//	     @Description    		Mold Agent를 제어합니다.
//			@param			action	path	string	true	"Agent action(start, stop)"
//	     @Tags                   License
//	     @Accept                 x-www-form-urlencoded
//	     @Produce                json
//	     @Success                200     {object}        LicenseList
//	     @Failure                400     {object}        httputil.HTTP400BadRequest
//	     @Failure                404     {object}        httputil.HTTP404NotFound
//	     @Failure                500     {object}        httputil.HTTP500InternalServerError
//	     @Router                 /api/v1/license/controlHostAgent/{action} [get]
func (c *Controller) ControlHostAgent(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")
	action := ctx.Param("action")
	if action == "start" {
		license.ControlHostAgent(true) //agent 시작
	} else {
		license.ControlHostAgent(false) //agent 정지
	}
	// license_data, err := license.ControlHostAgent("false")
	// if err != nil {
	// 	utils.FancyHandleError(err)
	// 	httputil.NewError(ctx, http.StatusInternalServerError, err)
	// 	return
	// }
	ctx.IndentedJSON(http.StatusOK, "license_data")
}
