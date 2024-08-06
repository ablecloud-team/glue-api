package model

/*
type MirrorList struct {
	AbleModel
}
*/

type MirrorImageItem struct {
	Interval  string `json:"interval"`
	StartTime string `json:"start_time"`
} //@name MirrorImageItem

type MirrorImage struct {
	Pool      string            `json:"pool"`
	Namespace string            `json:"namespace"`
	Image     string            `json:"image"`
	Items     []MirrorImageItem `json:"items"`
} //@name MirrorImage

type MirrorList struct {
	Local  []MirrorImage `json:"Local"`
	Remote []MirrorImage `json:"Remote"`
} //@name MirrorList

type MirrorSetup struct {
	LocalClusterName  string      `json:"localClusterName"`  //미러링 상태
	RemoteClusterName string      `json:"remoteClusterName"` //미러링 상태
	Host              string      `json:"host"`
	PrivateKeyFile    interface{} `json:"privateKeyFile" type:"file"`
	MirrorPool        string      `json:"mirrorPool"`
	LocalToken        string      `json:"localToken"`
	RemoteToken       string      `json:"remoteToken"`
} //@name MirrorSetup

type MirrorConf struct {
	Name            string `json:"name"`            //미러링 상태
	ClusterFileName string `json:"clusterFileName"` //미러링 데몬 상태
	KeyFileName     string `json:"keyFileName"`     //이미지 상태
	ClusterName     string `json:"clusterName"`     //이미지 상세
	Mode            string `json:"mode"`
	SiteName        string `json:"site_name"`
	Peers           []struct {
		Uuid       string `json:"uuid"`
		Direction  string `json:"direction"`
		SiteName   string `json:"site_name"`
		MirrorUuid string `json:"mirror_uuid"`
		ClientName string `json:"client_name"`
		Key        string `json:"key"`
		MonHost    string `json:"mon_host"`
	} `json:"peers"`
} //@name MirrorConf

type MirrorStatus struct {
	Health       string      `json:"health"`        //미러링 상태
	DaemonHealth string      `json:"daemon_health"` //미러링 데몬 상태
	ImageHealth  string      `json:"image_health"`  //이미지 상태
	States       interface{} `json:"states"`        //이미지 상세
} //@name MirrorStatus

type MirrorInfo struct {
	Mode     string `json:"mode"`
	SiteName string `json:"site_name"`
	Peers    []struct {
		Uuid       string `json:"uuid"`
		Direction  string `json:"direction"`
		SiteName   string `json:"site_name"`
		MirrorUuid string `json:"mirror_uuid"`
		ClientName string `json:"client_name"`
		Key        string `json:"key"`
		MonHost    string `json:"mon_host"`
	} `json:"peers"`
} // @name MirrorInfo

type MirrorToken struct {
	Fsid     string `json:"fsid"`
	ClientId string `json:"client_id"`
	Key      string `json:"key"`
	MonHost  string `json:"mon_host"`
} // @name MirrorToken

type AuthKey struct {
	Key string `json:"key"`
} //@name AuthKey

type SnapshotList struct {
	Images []Snapshot `json:"images"`
} // @name SnapshotList

type Snapshot struct {
	Image  string `json:"image"`
	Id     string `json:"id"`
	Size   int64  `json:"size"`
	Format int    `json:"format"`
} //@name Snapshot

type ImageMirror struct {
	Pool      string            `json:"pool"`
	Namespace string            `json:"namespace"`
	Image     string            `json:"image"`
	Items     []MirrorImageItem `json:"items"`
} //@name ImageMirror

type ImageStatus struct {
	Name          string `json:"name"`
	GlobalId      string `json:"global_id"`
	State         string `json:"state"`
	Description   string `json:"description"`
	DaemonService struct {
		ServiceId  string `json:"service_id"`
		InstanceId string `json:"instance_id"`
		DaemonId   string `json:"daemon_id"`
		Hostname   string `json:"hostname"`
	} `json:"daemon_service"`
	LastUpdate string `json:"last_update"`
	PeerSites  []struct {
		SiteName    string `json:"site_name"`
		MirrorUuids string `json:"mirror_uuids"`
		State       string `json:"state"`
		Description string `json:"description"`
		LastUpdate  string `json:"last_update"`
	} `json:"peer_sites"`
	Snapshots []struct {
		Id              int      `json:"id"`
		Name            string   `json:"name"`
		Demoted         bool     `json:"demoted"`
		MirrorPeerUuids []string `json:"mirror_peer_uuids"`
	} `json:"snapshots"`
} //@name ImageStatus

type ImageInfo struct {
	Name          string   `json:"name"`
	Id            string   `json:"id"`
	Size          int64    `json:"size"`
	SnapshotCount int64    `json:"snapshot_count"`
	Features      []string `json:"features"`
	Parent        struct {
		Pool     string `json:"pool"`
		Image    string `json:"image"`
		Snapshot string `json:"snapshot"`
	} `json:"parent"`
} //@name ImageInfo
