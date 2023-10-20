package waf

type buildContext struct {
	Version        string `json:"version,omitempty"`
	BuildTimestamp string `json:"buildTimestamp,omitempty"`
	Revision       string `json:"revision,omitempty"`
}

type siteContext[SiteT hasSite] struct {
	Site  SiteT         `json:"site"`
	Build *buildContext `json:"build,omitempty"`
}

func (s *Service[SiteT]) getSiteContext(site SiteT) siteContext[SiteT] {
	c := siteContext[SiteT]{
		Site:  site,
		Build: nil,
	}

	if c.Build.Version != "" || s.BuildTimestamp != "" || s.Revision != "" {
		c.Build = &buildContext{
			Version:        s.Version,
			BuildTimestamp: s.BuildTimestamp,
			Revision:       s.Revision,
		}
	}

	return c
}
