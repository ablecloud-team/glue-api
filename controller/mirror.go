package controller

import (
	"Glue-API/httputil"
	"Glue-API/model"
	"Glue-API/utils"
	"Glue-API/utils/mirror"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/melbahja/goph"
)

// MirrorImageList godoc
//
//	@Summary		Show List of Mirrored Snapshot
//	@Description	미러링중인 이미지의 목록과 상태를 보여줍니다.
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	model.MirrorList
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror/image [get]
func (c *Controller) MirrorImageList(ctx *gin.Context) {
	dat, err := mirror.ImageList()
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.IndentedJSON(http.StatusOK, dat)
}

// MirrorImageInfo godoc
//
//	@Summary		Show Infomation of Mirrored Snapshot
//	@Description	미러링중인 이미지의 정보를 보여줍니다.
//	@param			mirrorPool	path	string	true	"mirrorPool"
//	@param			imageName	path	string	true	"imageName"
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	model.ImageMirror
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror/image/{mirrorPool}/{imageName} [get]
func (c *Controller) MirrorImageInfo(ctx *gin.Context) {
	pool := ctx.Param("mirrorPool")
	image := ctx.Param("imageName")
	dat2, err := mirror.ImageList()
	var dat model.ImageMirror

	for _, mirrorImage := range append(dat2.Local, dat2.Remote...) {
		if mirrorImage.Pool == pool && mirrorImage.Image == image {
			dat.Items = mirrorImage.Items
			dat.Image = mirrorImage.Image
			dat.Namespace = mirrorImage.Namespace
			dat.Pool = mirrorImage.Pool
		}
	}
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.IndentedJSON(http.StatusOK, dat)
}

// MirrorImageDelete godoc
//
//	@Summary		Delete Mirrored Snapshot
//	@Description	이미지의 미러링을 비활성화 합니다.
//	@param			mirrorPool	path	string	true	"pool"
//	@param			imageName	path	string	true	"imageName"
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	controller.Message
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror/image/{mirrorPool}/{imageName} [delete]
func (c *Controller) MirrorImageDelete(ctx *gin.Context) {
	image := ctx.Param("imageName")
	pool := ctx.Param("mirrorPool")
	var output string

	output, err := mirror.ImageDelete(pool, image)

	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	output, err = mirror.ImagePreDelete(pool, image)

	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	ctx.IndentedJSON(http.StatusOK, Message{Message: output})
}

// MirrorStatus godoc
//
//	@Summary		Show Status of Mirror
//	@Description	Glue 의 미러링 상태를 보여줍니다.
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	model.MirrorStatus
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror [get]
func (c *Controller) MirrorStatus(ctx *gin.Context) {
	dat, err := mirror.Status()
	if err != nil {
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	// Print the output
	ctx.IndentedJSON(http.StatusOK, dat)
}

func (c *Controller) MirrorSetup(ctx *gin.Context) {
	var dat model.MirrorSetup

	dat.LocalClusterName, _ = ctx.GetPostForm("localClusterName")
	dat.RemoteClusterName, _ = ctx.GetPostForm("remoteClusterName")
	dat.Host, _ = ctx.GetPostForm("host")
	dat.MirrorPool, _ = ctx.GetPostForm("mirrorPool")
	file, _ := ctx.FormFile("privateKeyFile")
	privkey, err := os.CreateTemp("", "id_rsa-")
	defer privkey.Close()
	defer os.Remove(privkey.Name())
	privkeyname := privkey.Name()

	// Upload the file to specific dst.
	err = ctx.SaveUploadedFile(file, privkeyname)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	EncodedLocalToken, EncodedRemoteToken, err := mirror.ConfigMirror(dat, privkeyname)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	dat.LocalToken = EncodedLocalToken
	dat.RemoteToken = EncodedRemoteToken

	ctx.IndentedJSON(http.StatusOK, dat)
}

// MirrorDelete godoc
//
//	@Summary		Delete Mirroring Cluster
//	@Description	Glue 의 미러링 클러스터를 제거합니다.
//	@param			host			formData	string	true	"Remote Cluster Host Address"
//	@param			privateKeyFile	formData	file	true	"Remote Cluster PrivateKey"
//	@param			mirrorPool		formData	string	true	"Pool Name for Mirroring"
//	@Tags			Mirror
//	@Accept			multipart/form-data
//	@Produce		json
//	@Success		200	{object}	model.MirrorSetup
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror [delete]
func (c *Controller) MirrorDelete(ctx *gin.Context) {
	var dat model.MirrorSetup
	var EncodedLocalToken string
	var EncodedRemoteToken string
	var stdout []byte

	var out strings.Builder
	dat.Host, _ = ctx.GetPostForm("host")
	dat.MirrorPool, _ = ctx.GetPostForm("mirrorPool")
	file, _ := ctx.FormFile("privateKeyFile")

	privkey, err := os.CreateTemp("", "id_rsa-")
	defer privkey.Close()
	defer os.Remove(privkey.Name())
	privkeyname := privkey.Name()

	// Upload the file to specific dst.
	err = ctx.SaveUploadedFile(file, privkeyname)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	// Get Mirroring Images
	MirroredImage, err := mirror.ImageList()
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	for _, image := range MirroredImage.Local {
		_, errt := mirror.ImagePreDelete(image.Pool, image.Image)
		if errt != nil {
			err = errors.Join(err, errt)
		}
		_, errt = mirror.ImageDelete(image.Pool, image.Image)
		if errt != nil {
			err = errors.Join(err, errt)
		}
	}
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	for _, image := range MirroredImage.Remote {
		_, errt := mirror.ImageDelete(image.Pool, image.Image)
		if errt != nil {
			err = errors.Join(err, errt)
		}
	}
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	//remote local peer
	mirrorStatus, err := mirror.GetConfigure()

	if len(mirrorStatus.Peers) > 0 {
		peerUUID := mirrorStatus.Peers[0].Uuid
		cmd := exec.Command("rbd", "mirror", "pool", "peer", "remove", "--pool", dat.MirrorPool, peerUUID)
		// cmd.Stderr = &out
		stdout, err = cmd.CombinedOutput()
		println("out: " + string(stdout))
		println("err: " + out.String())
		// if err != nil || (out.String() != "" && out.String() != "rbd: mirroring is already configured for image mode") {
		if err != nil {
			cmd.Stderr = &out
			err = errors.Join(err, errors.New(out.String()))
			utils.FancyHandleError(err)
			httputil.NewError(ctx, http.StatusInternalServerError, err)
			return
		}
	}

	// Mirror Disable
	cmd := exec.Command("rbd", "mirror", "pool", "disable")
	// cmd.Stderr = &out
	stdout, err = cmd.CombinedOutput()
	if err != nil {
		cmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	// Mirror Daemon Destroy
	cmd = exec.Command("ceph", "orch", "rm", "rbd-mirror")
	// cmd.Stderr = &out
	stdout, err = cmd.CombinedOutput()
	if err != nil {
		cmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	//remote local peer
	out.Reset()
	client, err := utils.ConnectSSH(dat.Host, privkeyname)
	defer func(client *goph.Client) {
		err := client.Close()
		if err != nil {
			utils.FancyHandleError(err)
			httputil.NewError(ctx, http.StatusInternalServerError, err)
			return
		}
	}(client)
	remoteMirrorStatus, err := mirror.GetRemoteConfigure(client)

	if len(remoteMirrorStatus.Peers) > 0 {
		peerUUID := remoteMirrorStatus.Peers[0].Uuid
		sshcmd, err := client.Command("rbd", "mirror", "pool", "peer", "remove", "--pool", dat.MirrorPool, peerUUID)
		if err != nil {
			sshcmd.Stderr = &out
			err = errors.Join(err, errors.New(out.String()))
			utils.FancyHandleError(err)
			return
		}
		// sshcmd.Stderr = &out
		stdout, err = sshcmd.CombinedOutput()
		if err != nil {
			cmd.Stderr = &out
			err = errors.Join(err, errors.New(out.String()))
			utils.FancyHandleError(err)
			httputil.NewError(ctx, http.StatusInternalServerError, err)
			return
		}
	}

	// Mirror Disable
	sshcmd, err := client.Command("rbd", "mirror", "pool", "disable")
	if err != nil {
		sshcmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		return
	}
	stdout, err = sshcmd.CombinedOutput()
	if err != nil {
		cmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	// Mirror Daemon Destroy
	sshcmd, err = client.Command("ceph", "orch", "rm", "rbd-mirror")
	if err != nil {
		sshcmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		return
	}
	stdout, err = sshcmd.CombinedOutput()
	if err != nil {
		sshcmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	// Print the output
	dat.LocalToken = EncodedLocalToken
	dat.RemoteToken = EncodedRemoteToken
	ctx.IndentedJSON(http.StatusOK, dat)
}

// MirrorImageSetup godoc
//
//	@Summary		Setup Image Mirroring
//	@Description	Glue 의 이미지에 미러링을 설정합니다.
//	@param			mirrorPool	path		string	true	"Pool Name for Mirroring"
//	@param			imageName	path		string	true	"Image Name for Mirroring"
//	@param			interval	formData	string	true	"Interval of image snapshot"
//	@param			startTime	formData	string	false	"StartTime of image snapshot"
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	model.ImageMirror
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror/image/{mirrorPool}/{imageName} [post]
func (c *Controller) MirrorImageSetup(ctx *gin.Context) {
	//var dat model.MirrorSetup
	var dat = struct {
		Message string
	}{}

	//mirrorPool, _ := ctx.GetPostForm("mirrorPool")
	mirrorPool := ctx.Param("mirrorPool")
	imageName := ctx.Param("imageName")
	//imageName, _ := ctx.GetPostForm("imageName")
	interval, _ := ctx.GetPostForm("interval")
	startTime, _ := ctx.GetPostForm("startTime")
	print(startTime)

	message, err := mirror.ImagePreSetup(mirrorPool, imageName)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	message, err = mirror.ImageSetup(mirrorPool, imageName)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	message, err = mirror.ImageConfig(mirrorPool, imageName, interval, startTime)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	dat.Message = message
	ctx.IndentedJSON(http.StatusOK, dat)

}

// MirrorImageUpdate godoc
//
//	@Summary		Patch Image Mirroring
//	@Description	Glue 의 이미지에 미러링의 설정을 변경합니다.
//	@param			mirrorPool	path		string	true	"Pool Name for Mirroring"
//	@param			imageName	path		string	true	"Image Name for Mirroring"
//	@param			interval	formData	string	true	"Interval of image snapshot"
//	@param			startTime	formData	string	false	"Starttime of image snapshot"
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	model.ImageMirror
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror/image/{mirrorPool}/{imageName} [patch]
func (c *Controller) MirrorImageUpdate(ctx *gin.Context) {
	//var dat model.MirrorSetup
	var dat = struct {
		Message string
	}{}

	mirrorPool := ctx.Param("mirrorPool")
	imageName := ctx.Param("imageName")
	interval, _ := ctx.GetPostForm("interval")
	startTime, _ := ctx.GetPostForm("startTime")

	message, err := mirror.ImageConfig(mirrorPool, imageName, interval, startTime)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	dat.Message = message
	ctx.IndentedJSON(http.StatusOK, dat)
}

// MirrorImageStatus godoc
//
//	@Summary		Show Mirroring Image Status
//	@Description	Glue 의 이미지에 미러링상태를 확인합니다.
//	@param			mirrorPool	path	string	true	"Pool Name for Mirroring"
//	@param			imageName	path	string	true	"Image Name for Mirroring"
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	ImageStatus
//	@Failure		400	{object}	HTTP400BadRequest
//	@Failure		404	{object}	HTTP404NotFound
//	@Failure		500	{object}	HTTP500InternalServerError
//	@Router			/api/v1/mirror/image/status/{mirrorPool}/{imageName} [get]
func (c *Controller) MirrorImageStatus(ctx *gin.Context) {

	var dat model.ImageStatus

	mirrorPool := ctx.Param("mirrorPool")
	imageName := ctx.Param("imageName")

	dat, err := mirror.ImageStatus(mirrorPool, imageName)
	if err != nil {
		utils.FancyHandleError(err)
		print(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	print(dat.Description)
	ctx.IndentedJSON(http.StatusOK, dat)
}

// MirrorImagePromote godoc
//
//	@Summary		Promote Image Mirroring
//	@Description	Glue 의 이미지를 Promote 합니다.
//	@param			mirrorPool	path	string	true	"Pool Name for Mirroring"
//	@param			imageName	path	string	true	"Image Name for Mirroring"
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	model.ImageStatus
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror/image/promote/{mirrorPool}/{imageName} [post]
func (c *Controller) MirrorImagePromote(ctx *gin.Context) {

	var (
		dat model.ImageStatus
		err error
	)

	mirrorPool := ctx.Param("mirrorPool")
	imageName := ctx.Param("imageName")
	dat, err = mirror.RemoteImageDemote(mirrorPool, imageName)

	dat, err = mirror.ImageStatus(mirrorPool, imageName)

	dat, err = mirror.ImagePromote(mirrorPool, imageName)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	dat, err = mirror.ImageStatus(mirrorPool, imageName)
	if err != nil {
		utils.FancyHandleError(err)
		print(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.IndentedJSON(http.StatusOK, dat)
}

// MirrorImageDemote godoc
//
//	@Summary		Demote Image Mirroring
//	@Description	Glue 의 이미지를 Demote 합니다.
//	@param			mirrorPool	path	string	true	"Pool Name for Mirroring"
//	@param			imageName	path	string	true	"Image Name for Mirroring"
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	model.ImageStatus
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror/image/demote/{mirrorPool}/{imageName} [delete]
func (c *Controller) MirrorImageDemote(ctx *gin.Context) {

	var (
		dat model.ImageStatus
		err error
	)

	mirrorPool := ctx.Param("mirrorPool")
	imageName := ctx.Param("imageName")
	dat, err = mirror.ImageDemote(mirrorPool, imageName)

	dat, err = mirror.ImageStatus(mirrorPool, imageName)
	dat, err = mirror.RemoteImagePromote(mirrorPool, imageName)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	dat, err = mirror.ImageStatus(mirrorPool, imageName)
	if err != nil {
		utils.FancyHandleError(err)
		print(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	ctx.IndentedJSON(http.StatusOK, dat)
}

func (c *Controller) MirrorPoolEnable(ctx *gin.Context) {

	var dat model.MirrorSetup

	dat.LocalClusterName, _ = ctx.GetPostForm("localClusterName")
	dat.RemoteClusterName, _ = ctx.GetPostForm("remoteClusterName")
	dat.Host, _ = ctx.GetPostForm("host")
	dat.MirrorPool, _ = ctx.GetPostForm("mirrorPool")
	file, _ := ctx.FormFile("privateKeyFile")
	privkey, err := os.CreateTemp("", "id_rsa-")
	defer privkey.Close()
	defer os.Remove(privkey.Name())
	privkeyname := privkey.Name()

	// Upload the file to specific dst.
	err = ctx.SaveUploadedFile(file, privkeyname)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	EncodedLocalToken, EncodedRemoteToken, err := mirror.EnableMirror(dat, privkeyname)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	dat.LocalToken = EncodedLocalToken
	dat.RemoteToken = EncodedRemoteToken

	ctx.IndentedJSON(http.StatusOK, dat)

}

// MirrorPoolDisable godoc
//
//	@Summary		Disable Mirroring
//	@Description	Glue 의 미러링 클러스터를 비활성화합니다.
//	@param			host			formData	string	true	"Remote Cluster Host Address"
//	@param			privateKeyFile	formData	file	true	"Remote Cluster PrivateKey"
//	@param			mirrorPool		formData	string	true	"Pool Name for Mirroring"
//	@Tags			Mirror
//	@Accept			x-www-form-urlencoded
//	@Produce		json
//	@Success		200	{object}	model.ImageStatus
//	@Failure		400	{object}	httputil.HTTP400BadRequest
//	@Failure		404	{object}	httputil.HTTP404NotFound
//	@Failure		500	{object}	httputil.HTTP500InternalServerError
//	@Router			/api/v1/mirror/pool/{mirrorPool} [delete]
func (c *Controller) MirrorPoolDisable(ctx *gin.Context) {

	var dat model.MirrorSetup
	var EncodedLocalToken string
	var EncodedRemoteToken string
	var stdout []byte

	var out strings.Builder
	dat.Host, _ = ctx.GetPostForm("host")
	dat.MirrorPool, _ = ctx.GetPostForm("mirrorPool")
	file, _ := ctx.FormFile("privateKeyFile")

	privkey, err := os.CreateTemp("", "id_rsa-")
	defer privkey.Close()
	defer os.Remove(privkey.Name())
	privkeyname := privkey.Name()

	// Upload the file to specific dst.
	err = ctx.SaveUploadedFile(file, privkeyname)
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	// Get Mirroring Images
	MirroredImage, err := mirror.ImageList()
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	for _, image := range MirroredImage.Local {
		_, errt := mirror.ImageDelete(image.Pool, image.Image)
		if errt != nil {
			err = errors.Join(err, errt)
		}
		_, errt = mirror.ImagePreDelete(image.Pool, image.Image)
		if errt != nil {
			err = errors.Join(err, errt)
		}
	}
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}
	for _, image := range MirroredImage.Remote {
		_, errt := mirror.ImageDelete(image.Pool, image.Image)
		if errt != nil {
			err = errors.Join(err, errt)
		}
	}
	if err != nil {
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	//remote local peer
	mirrorStatus, err := mirror.GetConfigure()

	if len(mirrorStatus.Peers) > 0 {
		peerUUID := mirrorStatus.Peers[0].Uuid
		cmd := exec.Command("rbd", "mirror", "pool", "peer", "remove", "--pool", dat.MirrorPool, peerUUID)
		// cmd.Stderr = &out
		stdout, err = cmd.CombinedOutput()
		println("out: " + string(stdout))
		println("err: " + out.String())
		// if err != nil || (out.String() != "" && out.String() != "rbd: mirroring is already configured for image mode") {
		if err != nil {
			cmd.Stderr = &out
			err = errors.Join(err, errors.New(out.String()))
			utils.FancyHandleError(err)
			httputil.NewError(ctx, http.StatusInternalServerError, err)
			return
		}
	}

	// Mirror Disable
	cmd := exec.Command("rbd", "mirror", "pool", "disable")
	// cmd.Stderr = &out
	stdout, err = cmd.CombinedOutput()
	if err != nil {
		cmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	//remote local peer
	out.Reset()
	client, err := utils.ConnectSSH(dat.Host, privkeyname)
	defer func(client *goph.Client) {
		err := client.Close()
		if err != nil {
			utils.FancyHandleError(err)
			httputil.NewError(ctx, http.StatusInternalServerError, err)
			return
		}
	}(client)
	remoteMirrorStatus, err := mirror.GetRemoteConfigure(client)

	if len(remoteMirrorStatus.Peers) > 0 {
		peerUUID := remoteMirrorStatus.Peers[0].Uuid
		sshcmd, err := client.Command("rbd", "mirror", "pool", "peer", "remove", "--pool", dat.MirrorPool, peerUUID)
		if err != nil {
			sshcmd.Stderr = &out
			err = errors.Join(err, errors.New(out.String()))
			utils.FancyHandleError(err)
			return
		}
		// sshcmd.Stderr = &out
		stdout, err = sshcmd.CombinedOutput()
		if err != nil {
			cmd.Stderr = &out
			err = errors.Join(err, errors.New(out.String()))
			utils.FancyHandleError(err)
			httputil.NewError(ctx, http.StatusInternalServerError, err)
			return
		}
	}

	// Mirror Disable
	sshcmd, err := client.Command("rbd", "mirror", "pool", "disable")
	if err != nil {
		sshcmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		return
	}
	stdout, err = sshcmd.CombinedOutput()
	if err != nil {
		cmd.Stderr = &out
		err = errors.Join(err, errors.New(out.String()))
		utils.FancyHandleError(err)
		httputil.NewError(ctx, http.StatusInternalServerError, err)
		return
	}

	// Print the output
	dat.LocalToken = EncodedLocalToken
	dat.RemoteToken = EncodedRemoteToken
	ctx.IndentedJSON(http.StatusOK, dat)
}
