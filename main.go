package main

import (
	"Glue-API/controller"
	"Glue-API/docs"
	"Glue-API/httputil"
	"Glue-API/model"
	"Glue-API/utils"

	// "Glue-API/utils/license"
	"Glue-API/utils/mirror"
	"encoding/json"

	// "fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

//      @title                  Glue-API
//      @version                v1.0
//      @description    This is a GlueAPI server.
//      @termsOfService http://swagger.io/terms/

//      @contact.name   윤여천
//      @contact.url    http://www.ablecloud.io
//      @contact.email  support@ablecloud.io

//      @license.name   Apache 2.0
//      @license.url    http://www.apache.org/licenses/LICENSE-2.0.html

//      @BasePath       /api/v1

//      @securityDefinitions.basic      BasicAuth

//      @securityDefinitions.apikey     ApiKeyAuth
//      @in                                                     header
//      @name                                           Authorization
//      @description                            Description for what is this security definition being used

func main() {

	mold, _ := utils.ReadMoldFile()
	go MirroringSchedule(mold)
	// programmatically set swagger info

	// 로그 설정
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
	// logFile, err := os.OpenFile("/var/log/glue-api.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	// if err != nil {
	// 	fmt.Printf("로그 파일 열기 실패: %v\n", err)
	// 	return
	// }
	// defer logFile.Close()
	// log.SetOutput(logFile)
	// // 라이센스 체크 시작
	// password := "password"
	// salt := "salt"

	// if password == "" || salt == "" {
	// 	log.Println("라이센스 환경 변수가 설정되지 않았습니다")
	// 	return
	// }

	// success, err := license.StartLicenseCheck(password, salt)
	// log.Printf("라이센스 체크 실패\n")
	// // log.Printf(err.Error())
	// log.Printf(strconv.FormatBool(success))
	// if !success {
	// 	log.Printf("라이센스 체크 실패\n")
	// 	return
	// }

	docs.SwaggerInfo.Title = "Glue API"
	docs.SwaggerInfo.Description = "This is a GlueAPI server."
	docs.SwaggerInfo.Version = "1.0"
	//docs.SwaggerInfo.Host = ".swagger.io"
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{"https", "http"}

	httputil.Certify("cert.pem")

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	controller.LogSetting()
	r := gin.Default()
	r.ForwardedByClientIP = true
	r.SetTrustedProxies(nil)
	c := controller.NewController()
	v1 := r.Group("/api/v1")
	{
		glue := v1.Group("/glue")
		{
			glue.GET("", c.GlueStatus)
			glue.GET("/hosts", c.HostList)
			glue.GET("/version", c.GlueVersion)
			glue.GET("/pw", c.PwEncryption)
		}
		pool := v1.Group("/pool")
		{
			pool.GET("", c.ListPools)

			pool.DELETE("/:pool_name", c.PoolDelete)
			pool.OPTIONS("/:pool_name", c.GlueOption)
		}
		image := v1.Group("/image")
		{
			image.GET("", c.ListAndInfoImage)
			image.POST("", c.CreateImage)
			image.DELETE("", c.DeleteImage)
			image.OPTIONS("", c.GlueOption)
		}
		service := v1.Group("/service")
		{
			service.GET("", c.ServiceLs)

			service.POST("/:service_name", c.ServiceControl)
			service.DELETE("/:service_name", c.ServiceDelete)
			service.OPTIONS("/:service_name", c.GlueOption)
		}
		fs := v1.Group("/gluefs")
		{
			fs.GET("", c.FsStatus)
			fs.PUT("", c.FsUpdate)
			fs.OPTIONS("", c.FsOption)

			fs.POST("/:fs_name", c.FsCreate)
			fs.DELETE("/:fs_name", c.FsDelete)
			fs.OPTIONS("/:fs_name", c.FsOption)

			fs.GET("/info/:fs_name", c.FsGetInfo)

			subvolume := fs.Group("/subvolume")
			{
				// subvolume.GET("", c.SubVolumeList)
				// subvolume.POST("", c.SubVolumeCreate)
				// subvolume.DELETE("", c.SubVolumeDelete)
				// subvolume.PUT("", c.SubVolumeResize)
				// subvolume.OPTIONS("", c.SubVolumeOption)

				group := subvolume.Group("/group")
				{
					group.GET("", c.SubVolumeGroupList)
					group.POST("", c.SubVolumeGroupCreate)
					group.DELETE("", c.SubVolumeGroupDelete)
					group.PUT("", c.SubVolumeGroupResize)
					group.OPTIONS("", c.SubVolumeGroupOption)

					// group.DELETE("/snapshot", c.SubVolumeGroupSnapDelete
				}
				// snapshot := subvolume.Group("/snapshot")
				// {
				//      snapshot.GET("", c.SubVolumeSnapList)
				//      snapshot.POST("", c.SubVolumeSnapCreate)
				//      snapshot.DELETE("", c.SubVolumeSnapDelete)
				//      snapshot.OPTIONS("", c.SubVolumeOption)
				// }
			}
		}
		v1.POST("/ingress", c.IngressCreate)
		v1.PUT("/ingress", c.IngressUpdate)
		v1.OPTIONS("/ingress", c.NfsOption)

		nfs := v1.Group("/nfs")
		{
			nfs.GET("", c.NfsClusterList)

			nfs.POST("/:cluster_id/:port", c.NfsClusterCreate)
			nfs.PUT("/:cluster_id/:port", c.NfsClusterUpdate)
			nfs.OPTIONS("/:cluster_id/:port", c.NfsOption)

			nfs.DELETE("/:cluster_id", c.NfsClusterDelete)
			nfs.OPTIONS("/:cluster_id", c.NfsOption)

			nfs.POST("/ingress", c.IngressCreate)
			nfs.PUT("/ingress", c.IngressUpdate)
			nfs.OPTIONS("/ingress", c.NfsOption)

			nfs_export := nfs.Group("/export")
			{
				nfs_export.GET("", c.NfsExportDetailed)

				nfs_export.POST("/:cluster_id", c.NfsExportCreate)
				nfs_export.PUT("/:cluster_id", c.NfsExportUpdate)
				nfs_export.OPTIONS("/:cluster_id", c.NfsOption)

				nfs_export.DELETE("/:cluster_id/:export_id", c.NfsExportDelete)
				nfs_export.OPTIONS("/:cluster_id/:export_id", c.NfsOption)
			}
		}
		iscsi := v1.Group("/iscsi")
		{
			iscsi.POST("", c.IscsiServiceCreate)
			iscsi.PUT("", c.IscsiServiceUpdate)
			iscsi.OPTIONS("", c.IscsiOption)

			iscsi.GET("/discovery", c.IscsiGetDiscoveryAuth)
			iscsi.PUT("/discovery", c.IscsiUpdateDiscoveryAuth)
			iscsi.OPTIONS("/discovery", c.IscsiOption)

			iscsi_target := iscsi.Group("/target")
			{
				iscsi_target.GET("", c.IscsiTargetList)
				iscsi_target.DELETE("", c.IscsiTargetDelete)
				iscsi_target.POST("", c.IscsiTargetCreate)
				iscsi_target.PUT("", c.IscsiTargetUpdate)
				iscsi_target.OPTIONS("", c.IscsiOption)

				iscsi_target.DELETE("/purge", c.IscsiTargetPurge)
				iscsi_target.OPTIONS("/purge", c.IscsiOption)
			}

		}
		smb := v1.Group("/smb")
		{
			smb.GET("", c.SmbStatus)
			smb.POST("", c.SmbCreate)
			smb.DELETE("", c.SmbDelete)
			smb.OPTIONS("", c.SmbOption)
			smb_folder := smb.Group("/folder")
			{
				smb_folder.POST("", c.SmbShareFolderAdd)
				smb_folder.DELETE("", c.SmbShareFolderDelete)
				smb_folder.OPTIONS("", c.SmbOption)
			}
			smb_user := smb.Group("/user")
			{
				smb_user.POST("", c.SmbUserCreate)
				smb_user.PUT("", c.SmbUserUpdate)
				smb_user.DELETE("", c.SmbUserDelete)
				smb_user.OPTIONS("", c.SmbOption)
			}
		}
		rgw := v1.Group("/rgw")
		{
			rgw.GET("", c.RgwDaemon)
			rgw.POST("", c.RgwServiceCreate)
			rgw.PUT("", c.RgwServiceUpdate)
			rgw.OPTIONS("", c.RgwOption)
			rgw.POST("/quota", c.RgwQuota)

			user := rgw.Group("/user")
			{
				user.GET("", c.RgwUserList)
				user.POST("", c.RgwUserCreate)
				user.DELETE("", c.RgwUserDelete)
				user.PUT("", c.RgwUserUpdate)
				user.OPTIONS("", c.RgwOption)
			}
			bucket := rgw.Group("/bucket")
			{
				bucket.GET("", c.RgwBucketList)
				bucket.POST("", c.RgwBucketCreate)
				bucket.PUT("", c.RgwBucketUpdate)
				bucket.DELETE("", c.RgwBucketDelete)
				bucket.OPTIONS("", c.RgwOption)
			}
		}
		nvmeof := v1.Group("/nvmeof")
		{
			nvmeof.POST("", c.NvmeOfServiceCreate)

			nvmeof.POST("/image/download", c.NvmeOfImageDownload)

			nvmeof.GET("/target", c.NvmeOfTargetList)
			nvmeof.POST("/target", c.NvmeOfTargetCreate)

			subsystem := nvmeof.Group("/subsystem")
			{
				subsystem.GET("", c.NvmeOfSubSystemList)
				subsystem.POST("", c.NvmeOfSubSystemCreate)
				subsystem.DELETE("", c.NvmeOfSubSystemDelete)
				subsystem.OPTIONS("", c.NvmeOption)
			}
			namespace := nvmeof.Group("/namespace")
			{
				namespace.GET("", c.NvmeOfNameSpaceList)
				namespace.POST("", c.NvmeOfNameSpaceCreate)
				namespace.DELETE("", c.NvmeOfNameSpaceDelete)
				namespace.OPTIONS("", c.NvmeOption)
			}
		}
		mirror := v1.Group("/mirror")
		{
			mirror.GET("", c.MirrorStatus) //Get Mirroring Status
			//Todo
			mirror.POST("", c.MirrorSetup)                     //Setup Mirroring Cluster
			mirror.PUT("", c.MirrorUpdate)                     //Put Mirroring Cluster
			mirror.DELETE("", c.MirrorDelete)                  //Unconfigure Mirroring Cluster
			mirror.POST("/:mirrorPool", c.MirrorPoolEnable)    //Enable Mirroring Cluster
			mirror.DELETE("/:mirrorPool", c.MirrorPoolDisable) //Disable Mirroring Cluster
			mirrorgarbage := mirror.Group("/garbage")
			{
				mirrorgarbage.DELETE("", c.MirrorDeleteGarbage) //Delete Mirroring Cluster Garbage
			}
			mirrorimage := mirror.Group("/image")
			{
				mirrorimage.GET("/:mirrorPool", c.MirrorImageList)            //List Mirroring Images
				mirrorimage.GET("/:mirrorPool/:imageName", c.MirrorImageInfo) //Get Image Mirroring Info
				// mirrorimage.POST("/:mirrorPool/:imageName", c.MirrorImageSetup)                        //Setup Image Mirroring
				// mirrorimage.PUT("/:mirrorPool/:imageName", c.MirrorImageUpdate)                        //Config Image Mirroring
				// mirrorimage.DELETE("/:mirrorPool/:imageName", c.MirrorImageDelete)                	  //Unconfigure Image Mirroring
				mirrorimage.POST("/:mirrorPool/:imageName/:hostName/:vmName", c.MirrorImageScheduleSetup) //Setup Image Mirroring Schedule
				mirrorimage.DELETE("/:mirrorPool/:imageName", c.MirrorImageScheduleDelete)                //Unconfigure ImageMirroring Schedule
				mirrorimage.POST("/snapshot/:mirrorPool/:vmName", c.MirrorImageSnap)                      //Take Image Mirroring Snapshot or Setup Image Mirroring Snapshot Schedule
				mirrorimage.GET("/info/:mirrorPool/:imageName", c.MirrorImageParentInfo)                  //Get Image Mirroring Parent Info
				mirrorimage.GET("/status/:mirrorPool/:imageName", c.MirrorImageStatus)                    //Get Image Mirroring Status
				mirrorimage.POST("/promote/:mirrorPool/:imageName", c.MirrorImagePromote)                 //Promote Image
				mirrorimage.POST("/promote/peer/:mirrorPool/:imageName", c.MirrorImagePromotePeer)        //Promote Peer Image
				mirrorimage.DELETE("/demote/:mirrorPool/:imageName", c.MirrorImageDemote)                 //Demote Image
				mirrorimage.DELETE("/demote/peer/:mirrorPool/:imageName", c.MirrorImageDemotePeer)        //Demote Peer Image
				mirrorimage.PUT("/resync/:mirrorPool/:imageName", c.MirrorImageResync)                    //Resync Image
				mirrorimage.PUT("/resync/peer/:mirrorPool/:imageName", c.MirrorImageResyncPeer)           //Resync Peer Image
			}
		}
		gwvm := v1.Group("/gwvm")
		{
			gwvm.GET("/:hypervisorType", c.VmState)
			gwvm.GET("/detail/:hypervisorType", c.VmDetail)
			gwvm.POST("/:hypervisorType", c.VmSetup)        //Setup Gateway VM
			gwvm.PATCH("/start/:hypervisorType", c.VmStart) //Start to Gateway VM
			gwvm.OPTIONS("/start/:hypervisorType", c.VmStartOptions)
			gwvm.PATCH("/stop/:hypervisorType", c.VmStop) //Stop to Gateway VM
			gwvm.OPTIONS("/stop/:hypervisorType", c.VmStopOptions)
			gwvm.DELETE("/delete/:hypervisorType", c.VmDelete) //Delete to Gateway VM
			gwvm.OPTIONS("/delete/:hypervisorType", c.VmDeleteOptions)
			gwvm.PATCH("/cleanup/:hypervisorType", c.VmCleanup) //Cleanup to Gateway VM
			gwvm.OPTIONS("/cleanup/:hypervisorType", c.VmCleanupOptions)
			gwvm.PATCH("/migrate/:hypervisorType", c.VmMigrate) //Migrate to Gateway VM
			gwvm.OPTIONS("/migrate/:hypervisorType", c.VmMigrateOptions)
		}
		license := v1.Group("/license")
		{
			license.GET("", c.License)
			license.GET("/isLicenseExpired", c.IsLicenseExpired)
			license.GET("/controlHostAgent/:action", c.ControlHostAgent)
		}
		/*
		   admin := v1.Group("/admin")
		   {
		           admin.Use(auth())
		           admin.POST("/auth", c.Auth)
		   }
		*/
		r.Any("/version", c.Version)
	}
	settings, _ := utils.ReadConfFile()
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.RunTLS(":"+settings.ApiPort, "cert.pem", "key.pem")

}

/*
func auth() gin.HandlerFunc {
        return func(c *gin.Context) {
                if len(c.GetHeader("Authorization")) == 0 {
                        httputil.NewError(c, http.StatusUnauthorized, errors.New("Authorization is required Header"))
                        c.Abort()
                }
                c.Next()
        }
}
*/

func MirroringSchedule(mold model.Mold) {
	if mold.MoldUrl != "moldUrl" {
		var drResult map[string]interface{}
		var getDisasterRecoveryClusterList model.GetDisasterRecoveryClusterList
		var drInfo []byte
		for {
			drResult = utils.GetDisasterRecoveryClusterList()
			getDisasterRecoveryClusterList = model.GetDisasterRecoveryClusterList{}
			drInfo, _ = json.Marshal(drResult["getdisasterrecoveryclusterlistresponse"])
			json.Unmarshal([]byte(drInfo), &getDisasterRecoveryClusterList)
			if getDisasterRecoveryClusterList.Count != -1 {
				break
			}
			time.Sleep(5 * time.Minute)
		}
		json.Unmarshal([]byte(drInfo), &getDisasterRecoveryClusterList)
		if len(getDisasterRecoveryClusterList.Disasterrecoverycluster) > 0 {
			dr := getDisasterRecoveryClusterList.Disasterrecoverycluster
			for i := 0; i < len(dr); i++ {
				if len(dr[i].Drclustervmmap) > 0 {
					for j := 0; j < len(dr[i].Drclustervmmap); j++ {
						if dr[i].Drclustervmmap[j].Drclustermirrorvmvoltype == "ROOT" {
							params1 := []utils.MoldParams{
								{"keyword": dr[i].Drclustervmmap[j].Drclustermirrorvmname},
							}
							vmResult := utils.GetListVirtualMachinesMetrics(params1)
							listVirtualMachinesMetrics := model.ListVirtualMachinesMetrics{}
							vmInfo, _ := json.Marshal(vmResult["listvirtualmachinesmetricsresponse"])
							json.Unmarshal([]byte(vmInfo), &listVirtualMachinesMetrics)
							vm := listVirtualMachinesMetrics.Virtualmachine
							for k := 0; k < len(vm); k++ {
								var volList []string
								if vm[k].Name == dr[i].Drclustervmmap[j].Drclustermirrorvmname {
									vmName := vm[k].Instancename
									hostName := vm[k].Hostname
									volStatus, _ := mirror.ImageStatus("rbd", dr[i].Drclustervmmap[j].Drclustermirrorvmvolpath)
									// 미러링 이미지 상태가 Peer와 정상적으로 ready, sync 인 경우
									if volStatus.Description == "local image is primary" && strings.Contains(volStatus.PeerSites[0].State, "replaying") && strings.Contains(volStatus.PeerSites[0].Description, "idle") {
										interval, _ := mirror.ImageMetaGetInterval()
										meta, err := mirror.ImageMetaGetTime(dr[i].Drclustervmmap[j].Drclustermirrorvmvolpath)
										// 스케줄러가 실행되기 전에 glue-api 다운된 경우 처리
										if err != nil {
											params2 := []utils.MoldParams{
												{"virtualmachineid": vm[k].Id},
											}
											volResult := utils.GetListVolumes(params2)
											listVolumes := model.ListVolumes{}
											volInfo, _ := json.Marshal(volResult["listvolumesresponse"])
											json.Unmarshal([]byte(volInfo), &listVolumes)
											vol := listVolumes.Volume
											for l := 0; l < len(vol); l++ {
												volList = append(volList, vol[l].Path)
											}
											mirror.ImageMirroringSnap("rbd", hostName, vmName, volList)
											mirror.ImageConfigSchedule("rbd", dr[i].Drclustervmmap[j].Drclustermirrorvmvolpath, hostName, vmName, interval)
											meta, _ = mirror.ImageMetaGetTime(dr[i].Drclustervmmap[j].Drclustermirrorvmvolpath)
										}
										var volList []string
										info := strings.Split(meta, ",")
										host, _ := os.Hostname()
										params2 := []utils.MoldParams{
											{"virtualmachineid": vm[k].Id},
										}
										volResult := utils.GetListVolumes(params2)
										listVolumes := model.ListVolumes{}
										volInfo, _ := json.Marshal(volResult["listvolumesresponse"])
										json.Unmarshal([]byte(volInfo), &listVolumes)
										vol := listVolumes.Volume
										for l := 0; l < len(vol); l++ {
											volList = append(volList, vol[l].Path)
										}
										if host == strings.TrimRight(info[1], "\n") {
											mirror.ImageMirroringSnap("rbd", hostName, vmName, volList)
											mirror.ImageConfigSchedule("rbd", dr[i].Drclustervmmap[j].Drclustermirrorvmvolpath, hostName, vmName, interval)
										} else {
											local, _ := time.LoadLocation("Asia/Seoul")
											t, _ := time.ParseInLocation("2006-01-02 15:04:05", info[0], local)
											since := time.Since(t)
											var Ti time.Duration
											if strings.Contains(interval, "d") {
												intervals := strings.TrimRight(interval, "d\n")
												ti, _ := strconv.Atoi(intervals)
												Ti = time.Duration(ti) * 24 * time.Hour
											} else if strings.Contains(interval, "h") {
												intervals := strings.TrimRight(interval, "h\n")
												ti, _ := strconv.Atoi(intervals)
												Ti = time.Duration(ti) * time.Hour
											} else if strings.Contains(interval, "m") {
												intervals := strings.TrimRight(interval, "m\n")
												ti, _ := strconv.Atoi(intervals)
												Ti = time.Duration(ti) * time.Minute
											} else {
												Ti = time.Duration(1) * time.Hour
											}
											if since > Ti {
												mirror.ImageMirroringSnap("rbd", hostName, vmName, volList)
												message, err := mirror.ImageConfigSchedule("rbd", dr[i].Drclustervmmap[j].Drclustermirrorvmvolpath, hostName, vmName, interval)
												if err != nil {
													println(string(message))
												}
											}
										}
									}
									break
								}
							}
						}
					}
				}
			}
		}
	}
}
